from __future__ import absolute_import

from sentry.runner import configure
configure()

import functools
import logging
from collections import Counter, defaultdict
from datetime import timedelta

from django.db.models import F

from sentry.constants import DEFAULT_LOGGER_NAME, LOG_LEVELS_MAP
from sentry.event_manager import ScoreClause, generate_culprit, get_hashes_for_event, md5_from_hash
from sentry.models import Environment, Event, EventMapping, EventTag, EventUser, Group, GroupHash, GroupRelease, GroupTagKey, GroupTagValue, Release, UserReport
from sentry.tsdb import backend as tsdb


def update_group_for_event(group, event):
    if group is None:
        group = Group(
            project=event.project,
            short_id=event.project.next_short_id(),
            platform=event.platform,
            logger=event.get_tag('logger') or DEFAULT_LOGGER_NAME,
            first_seen=event.datetime,
            active_at=event.datetime,
            first_release=Release.objects.get(
                organization_id=event.project.organization_id,
                version=event.get_tag('sentry:release')
            ) if event.get_tag('sentry:release') else None,
            times_seen=0,
        )

    group.times_seen = group.times_seen + 1
    group.culprit = generate_culprit(event.data, event.platform)
    group.last_seen = event.datetime  # TODO: Verify this is last-write-wins!
    group.level = LOG_LEVELS_MAP.get(event.get_tag('level'), logging.ERROR)
    group.data = {
        'last_received': event.data.get('received') or float(event.datetime.strftime('%s')),
        'type': event.data['type'],
        'metadata': event.data['metadata'],
    }
    group.score = ScoreClause.calculate(
        group.times_seen,
        group.last_seen,
    )

    if event.message:
        group.message = event.message

    return group


def get_group_releases(group, events):
    attributes = {}

    def process_event(event):
        release = event.get_tag('sentry:release')
        if not release:
            return None

        # XXX: Not really clear what the canonical source is for environment
        # between the tag and the data attribute. Going with data attribute for
        # now.
        # NOTE: ``GroupRelease.environment`` is not nullable, but an empty
        # string is OK.
        environment = event.data.get('environment', '')

        key = (environment, release)
        if key in attributes:
            last_seen = attributes[key]['last_seen']
            attributes[key]['last_seen'] = event.datetime if last_seen < event.datetime - timedelta(seconds=60) else last_seen
        else:
            attributes[key] = {
                'environment': environment,
                'first_seen': event.datetime,
                'last_seen': event.datetime,
                'release_id': Release.objects.get(
                    organization_id=event.project.organization_id,
                    version=release,
                ).id,
            }

        return key

    keys = map(process_event, events)

    releases = {}
    for key, attributes in attributes.items():
        releases[key] = GroupRelease.objects.create(
            project_id=group.project_id,
            group_id=group.id,
            **attributes
        )

    return zip(
        events,
        map(releases.get, keys),
    )


def get_tag_data(events):
    def update_tags(tags, event):
        for key, value in event.get_tags():
            values = tags.setdefault(key, {})
            if value not in values:
                values[value] = (
                    1,
                    event.datetime,
                    event.datetime,
                    {event.group.id: 1},
                )
            else:
                count, first_seen, last_seen, sources = values[value]
                sources[event.group.id] = sources.get(event.group.id, 0) + 1
                values[value] = (
                    count + 1,
                    first_seen,
                    event.datetime,
                    sources,
                )
        return tags

    return reduce(
        update_tags,
        events,
        {},
    )


def get_tsdb_data(group, events):
    def collector((counters, sets, frequencies), (event, grouprelease)):
        counters[event.datetime][tsdb.models.group][group.id] += 1

        user = event.data.get('sentry.interfaces.User')
        if user:
            sets[event.datetime][tsdb.models.users_affected_by_group][group.id].add(
                EventUser(
                    project=event.group.project,
                    ident=user.get('id'),
                    email=user.get('email'),
                    username=user.get('username'),
                    ip_address=user.get('ip_address'),
                ).tag_value
            )

        environment = Environment.objects.get(
            projects=event.group.project,
            name=event.data.get('environment', ''),
        )

        frequencies[event.datetime][tsdb.models.frequent_environments_by_group][group.id][environment.id] += 1

        if grouprelease is not None:
            frequencies[event.datetime][tsdb.models.frequent_environments_by_group][group.id][grouprelease.id] += 1

        return counters, sets, frequencies

    return reduce(
        collector,
        events,
        (
            defaultdict(
                functools.partial(
                    defaultdict,
                    functools.partial(
                        defaultdict,
                        int,
                    ),
                )
            ),  # [timestamp][model][key] -> count
            defaultdict(
                functools.partial(
                    defaultdict,
                    functools.partial(
                        defaultdict,
                        set,
                    ),
                ),
            ),  # [timestamp][model][key] -> set(members)
            defaultdict(
                functools.partial(
                    defaultdict,
                    functools.partial(
                        defaultdict,
                        functools.partial(
                            defaultdict,
                            int,
                        ),
                    ),
                )
            ),  # [timestamp][model][key][value] -> count
        ),
    )


def unmerge(hashes, n=1000):
    queryset = Event.objects.filter(
        group_id__in=set(hash.group_id for hash in hashes),
    ).order_by('id')

    cursor = 0
    state = None
    while True:
        events = list(queryset.filter(id__gt=cursor)[:n])
        if not events:
            break  # XXX: Is there anything to do here?
        cursor = events[-1].id
        state = unmerge_events(state, hashes, events)
        if len(events) < n:
            break


def unmerge_events(state, hashes, events):
    # TODO: There are race conditions all over in here.

    Event.objects.bind_nodes(events, 'data')
    hash_values = set(hash.hash for hash in hashes)
    events = filter(
        lambda event: md5_from_hash(get_hashes_for_event(event)[0]) in hash_values,
        events,
    )

    # TODO: This doesn't rewrite any of the source group(s) attributes (e.g.
    # first and last seen, et al.)
    group = reduce(update_group_for_event, events, state)
    is_new = group.id is None  # XXX: Yuck
    group.save()
    if is_new:
        GroupHash.objects.filter(id__in=[hash.id for hash in hashes]).update(group=group)

    raise NotImplementedError

    sources = reduce(
        lambda sources, event: sources.update([event.group]) or sources,
        events,
        Counter()
    )

    for source, count in sources.items():
        source.update(times_seen=F('times_seen') - count)

    event_id_set = set(event.id for event in events)

    Event.objects.filter(id__in=event_id_set).update(group_id=group.id)
    EventTag.objects.filter(event_id__in=event_id_set).update(group_id=group.id)

    event_id_set = set(event.event_id for event in events)

    EventMapping.objects.filter(
        project_id=group.project_id,
        event_id__in=event_id_set,
    ).update(group_id=group.id)

    UserReport.objects.filter(
        project=group.project,
        event_id__in=event_id_set,
    ).update(group=group)

    for key, values in get_tag_data(events).items():
        GroupTagKey.objects.create(
            project=group.project,
            group=group,
            key=key,
            values_seen=len(values),
        )

        for value, (count, first_seen, last_seen, sources) in values.items():
            GroupTagValue.objects.create(
                project=group.project,
                group=group,
                times_seen=count,
                key=key,
                value=value,
                last_seen=first_seen,
                first_seen=last_seen,
            )

            for source, count in sources.items():
                record = GroupTagValue.objects.get(
                    project=group.project,
                    group=source,
                    key=key,
                    value=value,
                )
                record.times_seen = record.times_seen - count
                # TODO: This needs to either delete the source record, or
                # filter it from API responses if the `times_seen` is less than
                # 1. This also needs to account for race conditions.
                record.save()

            # TODO: This doesn't correct first or last seen on the source
            # `GroupTagValue`. record.

    events_with_releases = get_group_releases(group, events)

    counters, sets, frequencies = get_tsdb_data(group, events_with_releases)

    for timestamp, data in counters.items():
        for model, keys in data.items():
            for key, value in keys.items():
                tsdb.incr(model, key, timestamp, value)
                # TODO: This doesn't account for changes in the source group(s).

    for timestamp, data in sets.items():
        for model, keys in data.items():
            for key, values in keys.items():
                # TODO: This should use `record_multi` rather than `record`.
                # TODO: This doesn't account for changes in the source group(s).
                tsdb.record(model, key, values, timestamp)

    for timestamp, data in frequencies.items():
        tsdb.record_frequency_multi(data.items(), timestamp)

    # TODO: Create an activity record for both groups.
