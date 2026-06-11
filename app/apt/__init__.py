from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from app.models import APTCampaign, ThreatActor, IOC, Case
from app import db
from sqlalchemy import or_
import json

apt = Blueprint('apt', __name__)


@apt.route('/')
@login_required
def index():
    campaigns = APTCampaign.query.order_by(APTCampaign.start_date.desc()).all()
    actors = ThreatActor.query.order_by(ThreatActor.risk_score.desc()).all()
    return render_template('apt/index.html', campaigns=campaigns, actors=actors)


@apt.route('/campaigns')
@login_required
def campaigns():
    campaigns = APTCampaign.query.order_by(APTCampaign.start_date.desc()).all()
    return render_template('apt/campaigns.html', campaigns=campaigns)


@apt.route('/campaign/<int:id>')
@login_required
def campaign_detail(id):
    campaign = APTCampaign.query.get_or_404(id)
    if campaign.case_id:
        iocs = IOC.query.filter(
            or_(IOC.campaign == campaign.name, IOC.case_id == campaign.case_id)
        ).all()
    else:
        iocs = IOC.query.filter_by(campaign=campaign.name).all()
    ttps = []
    if campaign.ttps_used:
        try:
            ttps = json.loads(campaign.ttps_used)
        except:
            pass
    return render_template('apt/campaign_detail.html', campaign=campaign, iocs=iocs, ttps=ttps)


@apt.route('/actors')
@login_required
def actors():
    actors = ThreatActor.query.order_by(ThreatActor.risk_score.desc()).all()
    return render_template('apt/actors.html', actors=actors)


@apt.route('/actor/<int:id>')
@login_required
def actor_detail(id):
    actor = ThreatActor.query.get_or_404(id)
    campaigns = APTCampaign.query.filter_by(threat_actor_id=id).all()
    iocs = IOC.query.filter_by(threat_actor=actor.name).all()
    ttps = []
    tools = []
    if actor.ttps:
        try:
            ttps = json.loads(actor.ttps)
        except:
            pass
    if actor.tools:
        try:
            tools = json.loads(actor.tools)
        except:
            tools = actor.tools.split(',')
    return render_template('apt/actor_detail.html', actor=actor, campaigns=campaigns, iocs=iocs, ttps=ttps, tools=tools)


@apt.route('/mitre-attack')
@login_required
def mitre_attack():
    actors = ThreatActor.query.all()
    # Aggregate all TTPs
    all_ttps = {}
    for actor in actors:
        if actor.ttps:
            try:
                ttps = json.loads(actor.ttps)
                for ttp in ttps:
                    tid = ttp.get('id', '')
                    if tid not in all_ttps:
                        all_ttps[tid] = {'name': ttp.get('name', ''), 'actors': [], 'tactic': ttp.get('tactic', '')}
                    all_ttps[tid]['actors'].append(actor.name)
            except:
                pass
    return render_template('apt/mitre_attack.html', all_ttps=all_ttps, actors=actors)
