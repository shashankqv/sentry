from __future__ import absolute_import

from sentry.runner import configure
configure()

import functools
import logging

from django.db.models import F

from sentry.app import tsdb
from sentry.constants import DEFAULT_LOGGER_NAME, LOG_LEVELS_MAP
from sentry.event_manager import ScoreClause, generate_culprit, get_hashes_for_event, md5_from_hash
from sentry.models import Event, EventMapping, EventTag, Group, GroupHash, GroupRelease, GroupTagKey, GroupTagValue, Project, Release, UserReport
from sentry.utils.functional import apply_keys, collect


logger = logging.getLogger(__name__)


def unmerge(project, group_hashes, chunk=100):
    assert all(g.project_id == project.id for g in group_hashes)
    return unmerge_chunk(
        project.id,
        set([h.group_id for h in group_hashes]),
        set([h.id for h in group_hashes]),
        chunk,
        None,
        None,
    )


def build_fingerprint_matcher(group_hashes):
    values = set(hash.hash for hash in group_hashes)

    def predicate(event):
        return md5_from_hash(get_hashes_for_event(event)[0]) in values

    return predicate


initial_field_extractors = {
    'culprit': lambda event: generate_culprit(
        event.data,
        event.platform,
    ),
    'data': lambda event: {
        'last_received': event.data.get('received') or float(event.datetime.strftime('%s')),
        'type': event.data['type'],
        'metadata': event.data['metadata'],
    },
    'last_seen': lambda event: event.datetime,
    'level': lambda event: LOG_LEVELS_MAP.get(
        event.get_tag('level'),
        logging.ERROR,
    ),
    'message': lambda event: event.message,
    'times_seen': lambda event: 0,
}


update_field_extractors = {
    'platform': lambda fields, event: event.platform,
    'logger': lambda fields, event: event.get_tag('logger') or DEFAULT_LOGGER_NAME,
    'first_seen': lambda fields, event: event.datetime,
    'active_at': lambda fields, event: event.datetime,
    'first_release': lambda fields, event: Release.objects.get(
        organization_id=event.project.organization_id,  # XXX
        version=event.get_tag('sentry:release')
    ) if event.get_tag('sentry:release') else None,
    'times_seen': lambda fields, event: fields['times_seen'] + 1,
    'score': lambda fields, event: ScoreClause.calculate(
        fields['times_seen'] + 1,
        fields['last_seen'],
    ),
}


def get_group_field_values(project, fields, event):
    fields.update({name: f(fields, event) for name, f in update_field_extractors.items()})
    return fields


def collect_tag_data(events):
    def update_tags(tags, event):
        for key, value in event.get_tags():
            if key not in tags:
                values = tags[key] = {}
            else:
                values = tags[key]

            if value not in values:
                values[value] = (
                    1,
                    event.datetime,
                    event.datetime,
                    {event.group_id: 1},
                )
            else:
                count, first_seen, last_seen, sources = values[value]
                sources[event.group_id] = sources.get(event.group_id, 0) + 1
                values[value] = (
                    count + 1,
                    event.datetime,
                    last_seen,
                    sources,
                )
        return tags
    return reduce(
        update_tags,
        events,
        {},
    )


def get_group_releases(project, destination, events):
    attributes = {}

    def process_event(event):
        release = event.get_tag('sentry:release')
        if not release:
            return None

        # XXX: It's not really clear what the canonical source is for
        # environment between the tag and the data attribute, but I'm going
        # with data attribute for now. Right now it seems like they are
        # intended to both be present and the same value, but I'm not really
        # sure that has always been the case for existing values.
        # NOTE: ``GroupRelease.environment`` is not nullable, but an empty
        # string is OK.
        environment = event.data.get('environment', '')

        key = (
            environment,
            Release.objects.get(
                organization_id=project.organization_id,
                version=release,
            ).id,  # TODO: This isn't great, it should be cached or something.
        )

        if key in attributes:
            defaults, update = attributes[key]
            # TODO: This doesn't exactly match the behavior that is defined on
            # the model, but it's close enough for now.
            update['first_seen'] = event.datetime
        else:
            attributes[key] = ({
                'first_seen': event.datetime,
                'last_seen': event.datetime,
            }, {})

        return key

    keys = map(process_event, events)

    releases = {}
    for key, (defaults, update) in attributes.items():
        environment, release_id = key
        instance, created = GroupRelease.objects.get_or_create(
            project_id=project.id,
            group_id=destination.id,
            environment=environment,
            release_id=release_id,
            defaults=defaults,
        )

        if not created and update:
            instance.update(**update)

        releases[key] = instance

    return zip(
        events,
        map(
            releases.get,
            keys,
        ),
    )


def unmerge_chunk(project_id, source_group_ids, group_hash_ids, chunk, cursor, destination_id):
    project = Project.objects.get(id=project_id)

    queryset = Event.objects.order_by('-id').filter(
        project_id=project.id,
        group_id__in=source_group_ids,
    )

    if cursor is not None:
        queryset = queryset.filter(
            id__lt=cursor,
        )

    candidates = list(queryset[:chunk])

    if not candidates:
        GroupTagValue.objects.filter(
            group_id__in=source_group_ids,
            times_seen__lte=0,
        ).delete()

        instances = GroupTagKey.objects.filter(group_id__in=set(source_group_ids) | set([destination_id]))
        for instance in instances:
            instance.update(
                values_seen=GroupTagValue.objects.filter(
                    project_id=instance.project_id,
                    group_id=instance.group_id,
                    key=instance.key,
                ).count(),
            )

        GroupTagKey.objects.filter(
            id__in=set(instance.id for instance in instances),
            values_seen__lte=0,
        ).delete()

        GroupHash.objects.filter(
            id__in=group_hash_ids,
            state=GroupHash.State.MIGRATION_IN_PROGRESS,
        ).update(state=GroupHash.State.ACTIVE)

        return

    Event.objects.bind_nodes(candidates, 'data')

    group_hashes = GroupHash.objects.filter(
        project=project,
        id__in=group_hash_ids,
    )

    requires_migration = build_fingerprint_matcher(group_hashes)

    def collect_events(result, event):
        result[requires_migration(event)].append(event)
        return result

    events_to_repair, events_to_migrate = reduce(
        collect_events,
        candidates,
        ([], []),
    )

    if events_to_migrate:
        if destination_id is None:
            destination = Group.objects.create(
                project_id=project.id,
                short_id=project.next_short_id(),
                **reduce(
                    functools.partial(
                        get_group_field_values,
                        project,
                    ),
                    events_to_migrate,
                    {name: f(events_to_migrate[0]) for name, f in initial_field_extractors.items()},
                )
            )
            destination_id = destination.id

            GroupHash.objects.filter(
                project=project,
                id__in=group_hash_ids,
                state=GroupHash.State.ACTIVE,  # TODO: Assert before starting
            ).update(
                group=destination,
                state=GroupHash.State.MIGRATION_IN_PROGRESS,
            )

            tsdb.delete([
                tsdb.models.group,
            ], source_group_ids)

            tsdb.delete_distinct_counts([
                tsdb.models.users_affected_by_group,
            ], source_group_ids)

            tsdb.delete_frequencies([
                tsdb.models.frequent_releases_by_group,
                tsdb.models.frequent_environments_by_group,
            ], source_group_ids)
        else:
            destination = Group.objects.get(
                project=project,
                id=destination_id,
            )
            destination.update(
                **reduce(
                    functools.partial(
                        get_group_field_values,
                        project,
                    ),
                    events_to_migrate,
                    {name: getattr(destination, name) for name in set(initial_field_extractors.keys()) | set(update_field_extractors.keys())},
                )
            )

        events_by_source = apply_keys(
            lambda keys: map(Group.objects.in_bulk(keys).get, keys),
            collect(
                lambda event: event.group_id,
                events_to_migrate,
            )
        )

        # TODO: handle unlikely None case
        for source, items in events_by_source.items():
            source.update(
                times_seen=F('times_seen') - len(items),
            )

        event_id_set = set(event.id for event in events_to_migrate)

        Event.objects.filter(
            project_id=project.id,
            id__in=event_id_set,
        ).update(group_id=destination.id)

        EventTag.objects.filter(
            project_id=project.id,
            event_id__in=event_id_set,
        ).update(group_id=destination.id)

        event_event_id_set = set(event.event_id for event in events_to_migrate)

        EventMapping.objects.filter(
            project_id=project.id,
            event_id__in=event_event_id_set,
        ).update(group_id=destination.id)

        UserReport.objects.filter(
            project=project,
            event_id__in=event_event_id_set,
        ).update(group=destination)

        for key, values in collect_tag_data(events_to_migrate).items():
            # TODO: This might need to repair the `first_seen` and `last_seen`
            # columns on the source group(s)?

            GroupTagKey.objects.get_or_create(
                project=project,
                group=destination,
                key=key,
            )

            for value, (times_seen, first_seen, last_seen, sources) in values.items():
                instance, created = GroupTagValue.objects.get_or_create(
                    project=project,
                    group=destination,
                    key=key,
                    value=value,
                    defaults={
                        'first_seen': first_seen,
                        'last_seen': last_seen,
                        'times_seen': times_seen,
                    },
                )

                if not created:
                    instance.update(
                        first_seen=first_seen,
                        times_seen=F('times_seen') + times_seen,
                    )

                for source_id, count in sources.items():
                    # TODO: Protect against running negative.
                    # TODO: What happens if this doesn't actually affect any rows?
                    GroupTagValue.objects.filter(
                        project=project,
                        group_id=source_id,
                        key=key,
                        value=value,
                    ).update(
                        times_seen=F('times_seen') - count,
                    )

        get_group_releases(project, destination, events_to_migrate)

        # TODO: Handle TSDB.

    return unmerge_chunk(
        project_id,
        source_group_ids,
        group_hash_ids,
        chunk,
        candidates[-1].id,
        destination_id,
    )
