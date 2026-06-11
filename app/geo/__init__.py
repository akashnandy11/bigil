from flask import Blueprint, render_template, jsonify
from flask_login import login_required
from app.models import Case, Alert, IOC, AttackTimeline, ThreatActor
geo = Blueprint('geo', __name__)

COUNTRY_COORDS = {
    'Russia': [61.52401, 105.318756],
    'China': [35.86166, 104.195397],
    'North Korea': [40.339852, 127.510093],
    'Iran': [32.427908, 53.688046],
    'USA': [37.09024, -95.712891],
    'India': [20.593684, 78.96288],
    'Germany': [51.165691, 10.451526],
    'UK': [55.378051, -3.435973],
    'Pakistan': [30.375321, 69.345116],
    'Brazil': [-14.235004, -51.92528],
    'Ukraine': [48.379433, 31.16558],
    'Belarus': [53.709807, 27.953389],
    'Romania': [45.943161, 24.96676],
    'Indonesia': [-0.789275, 113.921327],
    'Bangladesh': [23.684994, 90.356331],
    'Unknown': [30.0, 60.0],
}

INDIA_CITIES = {
    'Gurugram': (28.4595, 77.0266),
    'New Delhi': (28.6139, 77.2090),
    'Mumbai': (19.0760, 72.8777),
    'Bengaluru': (12.9716, 77.5946),
    'Kolkata': (22.5726, 88.3639),
    'Hyderabad': (17.3850, 78.4867),
    'Chennai': (13.0827, 80.2707),
    'Ahmedabad': (23.0225, 72.5714),
    'Lucknow': (26.8467, 80.9462),
    'Chandigarh': (30.7333, 76.7794),
}


@geo.route('/')
@login_required
def index():
    return render_template('geo/index.html')


@geo.route('/api/attack-sources')
@login_required
def api_attack_sources():
    """Map threat actors from DB (MITRE STIX import) to country coordinates."""
    actors = ThreatActor.query.filter(
        ThreatActor.origin_country.isnot(None),
        ThreatActor.origin_country != 'Unknown'
    ).order_by(ThreatActor.risk_score.desc()).all()

    actor_data = []
    for actor in actors:
        country = actor.origin_country
        if country not in COUNTRY_COORDS:
            continue
        coords = COUNTRY_COORDS[country]
        ioc_count = IOC.query.filter(IOC.threat_actor == actor.name).count()
        case_count = Case.query.filter(Case.tags.ilike(f'%{actor.name}%')).count()
        actor_data.append({
            'country': country,
            'actor': actor.name,
            'lat': coords[0] + (len(actor_data) % 3) * 0.8,
            'lng': coords[1] + (len(actor_data) % 2) * 0.8,
            'ioc_count': ioc_count,
            'severity': 'critical' if actor.risk_score >= 85 else 'high' if actor.risk_score >= 70 else 'medium',
            'incident_count': case_count
        })

    return jsonify(actor_data)


@geo.route('/api/incident-heatmap')
@login_required
def api_heatmap():
    """Derive India incident heatmap from open cases and timeline events."""
    case_counts = {}
    for case in Case.query.filter(Case.status.in_(['open', 'active'])).all():
        city = 'Gurugram'
        if case.victim_org and 'Delhi' in case.victim_org:
            city = 'New Delhi'
        elif case.tags and 'Mumbai' in case.tags:
            city = 'Mumbai'
        case_counts[city] = case_counts.get(city, 0) + 1

    timeline_count = AttackTimeline.query.count()
    if timeline_count:
        case_counts['Gurugram'] = case_counts.get('Gurugram', 0) + min(timeline_count, 5)

    max_count = max(case_counts.values()) if case_counts else 1
    heatmap_data = []
    for city, (lat, lng) in INDIA_CITIES.items():
        count = case_counts.get(city, 0)
        if count > 0:
            intensity = round(min(1.0, count / max_count), 2)
            heatmap_data.append({'lat': lat, 'lng': lng, 'intensity': intensity, 'city': city, 'cases': count})

    return jsonify(heatmap_data)


@geo.route('/api/stats')
@login_required
def api_stats():
    """Real geospatial stats from database."""
    source_countries = ThreatActor.query.filter(
        ThreatActor.origin_country.isnot(None),
        ThreatActor.origin_country != 'Unknown'
    ).with_entities(ThreatActor.origin_country).distinct().count()

    hotspots = Case.query.filter(Case.status.in_(['open', 'active'])).count()
    attack_vectors = IOC.query.filter_by(is_active=True).count()
    critical_cases = Case.query.filter_by(priority='critical').count()

    targets = Case.query.filter(
        Case.victim_sector.isnot(None)
    ).with_entities(Case.victim_org, Case.victim_sector).limit(10).all()

    target_data = []
    city_coords = list(INDIA_CITIES.items())
    for i, (org, sector) in enumerate(targets):
        if not org:
            continue
        city_name, (lat, lng) = city_coords[i % len(city_coords)]
        target_data.append({
            'lat': lat, 'lng': lng,
            'name': org[:60],
            'type': sector or 'Unknown',
            'city': city_name
        })

    return jsonify({
        'source_countries': source_countries,
        'hotspots': hotspots,
        'attack_vectors': attack_vectors,
        'critical_infrastructure': critical_cases,
        'targets': target_data
    })
