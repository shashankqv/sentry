"""
sentry.models.grouphash
~~~~~~~~~~~~~~~~~~~~~~~

:copyright: (c) 2010-2014 by the Sentry Team, see AUTHORS for more details.
:license: BSD, see LICENSE for more details.
"""
from __future__ import absolute_import

from django.db import models
from django.utils.translation import ugettext_lazy as _

from sentry.db.models import BoundedPositiveIntegerField, FlexibleForeignKey, Model


class GroupHash(Model):
    __core__ = False

    class State:
        ACTIVE = 0
        MIGRATION_IN_PROGRESS = 1

    project = FlexibleForeignKey('sentry.Project', null=True)
    hash = models.CharField(max_length=32)
    group = FlexibleForeignKey('sentry.Group', null=True)
    state = BoundedPositiveIntegerField(
        choices=(
            (State.ACTIVE, _('Active')),
            (State.MIGRATION_IN_PROGRESS, _('Migration in Progress')),
        ),
        default=State.ACTIVE,
    )

    class Meta:
        app_label = 'sentry'
        db_table = 'sentry_grouphash'
        unique_together = (('project', 'hash'),)
