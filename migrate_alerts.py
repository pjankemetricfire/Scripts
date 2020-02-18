#!/usr/bin/env python
import json
import os

from alerting.models import Alert

from grafana.utils import GrafanaRequest
from grafana.views import grafana_admin_login_request
from django.db import transaction, IntegrityError
from Graphite.app.models import UserProfile
import logging

requester = GrafanaRequest()

USER_ID = os.environ.get("account_uid", None)

def get_owner(userid):
    try:
        userProfile = UserProfile.objects.get(uid = userid)
        owner = userProfile.user
    except UserProfile.DoesNotExist as e:
        return e
    return owner

def migrate_alerts():
    """The only purpose of this script is to be run manually to migrate all alerts from Grafana to Hostedgraphite
    We need this because after disabling alerting system, dashboards which contain alerts will become inaccessible
    """
        
    try:
        if USER_ID is not None:
            alerts_with_grafana_configs = Alert.objects.filter(source__contains='grafana_conf').filter(owner=get_owner(USER_ID)).select_for_update()
        else:
            alerts_with_grafana_configs = Alert.objects.filter(source__contains='grafana_conf').select_for_update()
    except Exception:
        logging.warning("USER ID does not exist: %s" % USER_ID)
        print("Error, UID does not exist: %s" % USER_ID)
        raise SystemExit

    dashboards_to_remove_alerts = []
    for alert in alerts_with_grafana_configs:
        source = alert.source_dict
        dashboards_to_remove_alerts.append({'user': alert.owner, 'grafana_conf': alert.grafana_config})

        del source['grafana_conf']
        source['tags'] = []
        if source.get('uuid', False):
            del source['uuid']

        alert.source = json.dumps(source)
        alert.save()
        print('Updated alert uuid=%s user=%s' % (alert.uuid, alert.owner.userprofile.uid))

    remove_alerts_from_dashboards(dashboards_to_remove_alerts)


def remove_alerts_from_dashboards(dashboards_to_remove_alerts):
    processed_dashboard_uids = []

    for dashboard_info in dashboards_to_remove_alerts:
        user = dashboard_info['user']
        grafana_port = user.userprofile.grafana_config.container_port
        uid = user.userprofile.uid
        pug_admin_login = grafana_admin_login_request(uid, grafana_port)
        if not pug_admin_login.ok:
            raise IntegrityError('Admin login failed uid=%s port=%s' % (uid, str(grafana_port)))
        auth_cookies = pug_admin_login.cookies

        dashboards_res = requester.get('api/search', grafana_port, cookies=auth_cookies)
        all_dashboards = dashboards_res.json()
        dashboard_id = dashboard_info['grafana_conf']['dashboard_id']
        dashboard_lookup = next((d for d in all_dashboards if d['id'] == dashboard_id), None)
        if dashboard_lookup is None:
            raise IntegrityError('Dashboard not found user=%s  id=%s' % (uid, dashboard_id))

        dashboard_uid = dashboard_lookup['uid']
        if dashboard_uid not in processed_dashboard_uids:
            dashboard_res = requester.get('api/dashboards/uid/' + dashboard_uid,
                                          grafana_port, cookies=auth_cookies).json()
            dashboard = dashboard_res['dashboard']

            del dashboard['alertPanelMap']
            panels = dashboard['panels']
            for panel in panels:
                panel['thresholds'] = []

            update_request_body = json.dumps({
                'dashboard': dashboard,
                'message': 'Remove alerts from dashboard due to disabling Grafana alerting',
                'overwrite': True
            })
            dash_update_res = requester.post('api/dashboards/db/', grafana_port,
                                             data=update_request_body, cookies=auth_cookies)
            if dash_update_res.ok and dash_update_res.json()['status'] == 'success':
                print('Removed alerts from dashboard uid=%s user=%s' % (dashboard_uid, uid))
                processed_dashboard_uids.append(dashboard_uid)
            else:
                raise IntegrityError('Failed to update dashboard')

    print(processed_dashboard_uids)
    # IMPORTANT!!!
    # Remove this before running on real data, raising exception here makes django revert all db changes    
    raise IntegrityError('Dashboards updated successfully!')


with transaction.atomic():
    migrate_alerts()
