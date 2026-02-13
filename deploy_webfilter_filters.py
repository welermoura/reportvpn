import os
import base64
import subprocess

# HTML Content:
# FORCE HORIZONTAL LAYOUT FOR FILTERS using display: flex
html_content = """{% extends 'dashboard/base.html' %}
{% load static %}

{% block title %}Web Filter Dashboard{% endblock %}

{% block content %}
<div class="container-fluid py-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h1>Filtro de Conteudo Web</h1>
        <div>
            <a href="{% url 'security_events:export_pdf' %}?{{ request.GET.urlencode }}&event_type=webfilter" class="btn btn-danger shadow-sm me-2 fw-bold" target="_blank">
                <i class="fas fa-file-pdf me-1"></i> PDF
            </a>
            <a href="{% url 'security_events:export_csv' %}?{{ request.GET.urlencode }}&event_type=webfilter" class="btn btn-success shadow-sm me-2 fw-bold">
                <i class="fas fa-file-csv me-1"></i> CSV
            </a>
            <a href="{% url 'security_events:index' %}" class="btn btn-outline-secondary fw-bold">Voltar ao Geral</a>
        </div>
    </div>

    <!-- Stats Cards: CSS GRID (2 columns) -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 2rem;">
        <div class="card bg-dark text-white shadow" style="height: 100%;">
            <div class="card-body d-flex flex-column justify-content-center">
                <h5 class="card-title text-danger text-uppercase small fw-bold">Acessos Bloqueados</h5>
                <div class="d-flex align-items-baseline">
                    <h2 class="mb-0 display-6 fw-bold">{{ total_blocks|default:0 }}</h2>
                    <small class="text-muted ms-2">/ {{ days }} dias</small>
                </div>
            </div>
        </div>
        <div class="card bg-dark text-white shadow" style="height: 100%;">
            <div class="card-body d-flex flex-column justify-content-center">
                <h5 class="card-title text-info text-uppercase small fw-bold">Total de Eventos Web</h5>
                <h2 class="mb-0 display-6 fw-bold">{{ total_events|default:0 }}</h2>
                <small class="text-muted">Monitoramento HTTP/HTTPS</small>
            </div>
        </div>
    </div>

    <!-- Charts Section: CSS GRID (2 columns) -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 2rem;">
        <div class="card bg-dark text-white shadow" style="height: 100%; overflow: hidden;">
            <div class="card-header border-bottom-secondary py-2 small fw-bold text-uppercase">Top Categorias Bloqueadas</div>
            <div class="card-body">
                <div style="position: relative; height: 250px; width: 100%;">
                    <canvas id="webCategoryChart"></canvas>
                </div>
            </div>
        </div>
        <div class="card bg-dark text-white shadow" style="height: 100%; overflow: hidden;">
            <div class="card-header border-bottom-secondary py-2 small fw-bold text-uppercase">Top Sites Bloqueados</div>
            <div class="card-body">
                <div style="position: relative; height: 250px; width: 100%;">
                    <canvas id="webUrlChart"></canvas>
                </div>
            </div>
        </div>
    </div>

    <!-- Filters & Table Section -->
    <div class="card bg-dark text-white shadow">
        <!-- Filter Header / Toolbar: FORCED FLEX ROW -->
        <div class="card-header border-bottom-secondary p-3">
            <form method="get" style="display: flex; flex-direction: row; align-items: center; gap: 10px; flex-wrap: nowrap; overflow-x: auto;">
                <input type="hidden" name="days" value="{{ days }}">
                <input type="hidden" name="ordering" value="{{ ordering }}">
                
                <div style="white-space: nowrap; font-weight: bold; text-transform: uppercase; font-size: 0.85em; margin-right: 5px;">
                    <i class="fas fa-filter me-1"></i> Filtros:
                </div>
                
                <div style="flex: 1; min-width: 150px;">
                    <input type="text" name="username" class="form-control form-control-sm bg-dark border-secondary text-white" value="{{ username_q }}" placeholder="Usuário...">
                </div>
                <div style="flex: 1; min-width: 150px;">
                    <input type="text" name="url" class="form-control form-control-sm bg-dark border-secondary text-white" value="{{ url_q }}" placeholder="Site / URL...">
                </div>
                <div style="flex: 1; min-width: 150px;">
                    <select name="category" class="form-select form-select-sm bg-dark border-secondary text-white">
                        <option value="">Categoria: Todas</option>
                        {% for cat in all_categories %}
                        <option value="{{ cat }}" {% if category == cat %}selected{% endif %}>{{ cat }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div style="flex: 1; min-width: 150px;">
                    <select name="action" class="form-select form-select-sm bg-dark border-secondary text-white">
                        <option value="">Ação: Todas</option>
                        <option value="blocked" {% if action == 'blocked' %}selected{% endif %}>Bloqueado</option>
                        <option value="passthrough" {% if action == 'passthrough' %}selected{% endif %}>Permitido</option>
                    </select>
                </div>
                <div>
                    <button type="submit" class="btn btn-primary btn-sm px-3">Filtrar</button>
                    <a href="{% url 'security_events:webfilter' %}" class="btn btn-outline-secondary btn-sm"><i class="fas fa-times"></i></a>
                </div>
            </form>
        </div>

        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-dark table-hover align-middle mb-0" style="border-collapse: collapse;">
                    <thead class="bg-secondary text-uppercase small">
                        <tr>
                            <th class="ps-3 py-3"><a href="?{{ request.GET.urlencode }}&ordering={% if ordering == 'timestamp' %}-timestamp{% else %}timestamp{% endif %}" class="text-white text-decoration-none">Data/Hora <i class="fas fa-sort"></i></a></th>
                            <th class="py-3">Usuário</th>
                            <th class="py-3">Cargo</th>
                            <th class="py-3">Departamento</th>
                            <th class="py-3">Categoria</th>
                            <th class="py-3">Ação</th>
                            <th class="py-3">URL</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for event in events %}
                        <tr class="border-bottom border-secondary">
                            <td class="ps-3 text-nowrap text-secondary">{{ event.timestamp|date:"d/m/Y H:i:s" }}</td>
                            <td>
                                <!-- USER COLUMN: FORCE BLOCK DISPLAY -->
                                <div>
                                    {% if event.ad_display_name %}
                                        <div style="display: block; font-weight: bold; font-size: 1.05em; color: white; margin-bottom: 1px;">
                                            {{ event.ad_display_name }}
                                        </div>
                                        <div style="display: block; font-size: 0.8em; color: #6c757d;">
                                            {{ event.username }}
                                        </div>
                                    {% else %}
                                        <div style="display: block; font-weight: bold; font-size: 1.05em; color: white;">
                                            {{ event.username|default:"-" }}
                                        </div>
                                    {% endif %}
                                </div>
                            </td>
                            <td>
                                {% if event.ad_title %}
                                    <span class="text-light small">{{ event.ad_title }}</span>
                                {% else %}
                                    <span class="text-muted small">-</span>
                                {% endif %}
                            </td>
                            <td>
                                {% if event.user_department %}
                                <span class="text-info small">{{ event.user_department }}</span>
                                {% else %}
                                <span class="text-muted small">-</span>
                                {% endif %}
                            </td>
                            <td><span class="badge bg-info">{{ event.category }}</span></td>
                            <td>
                                {% if event.action == 'block' or event.action == 'blocked' %}
                                <span class="badge bg-danger">Bloqueado</span>
                                {% else %}
                                <span class="badge bg-success">{{ event.action }}</span>
                                {% endif %}
                            </td>
                            <td title="{{ event.url }}">
                                <div style="max-width: 250px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" class="text-light">
                                    {{ event.url }}
                                </div>
                            </td>
                        </tr>
                        {% empty %}
                        <tr>
                            <td colspan="7" class="text-center py-5">
                                <h4 class="text-muted">Nenhum evento encontrado</h4>
                                <p class="text-muted small">Tente ajustar os filtros acima.</p>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
{{ top_categories|json_script:"category-data" }}
{{ top_urls|json_script:"url-data" }}

<script>
    document.addEventListener('DOMContentLoaded', function() {
        const commonOptions = {
            maintainAspectRatio: false,
            responsive: true,
            indexAxis: 'y', // Horizontal bars for both
            scales: {
                x: { ticks: { color: '#adb5bd' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                y: { ticks: { color: '#fff', font: { size: 11 } }, grid: { display: false } }
            },
            plugins: {
                legend: { display: false }
            }
        };

        // 1. Categories Chart (Horizontal Bar)
        const catData = JSON.parse(document.getElementById('category-data').textContent);
        if (catData.length > 0) {
            new Chart(document.getElementById('webCategoryChart'), {
                type: 'bar',
                data: {
                    labels: catData.map(d => d.category),
                    datasets: [{
                        label: 'Eventos',
                        data: catData.map(d => d.count),
                        backgroundColor: 'rgba(54, 185, 204, 0.8)',
                        borderRadius: 4
                    }]
                },
                options: commonOptions
            });
        }

        // 2. URLs Chart (Horizontal Bar)
        const urlData = JSON.parse(document.getElementById('url-data').textContent);
        if (urlData.length > 0) {
            new Chart(document.getElementById('webUrlChart'), {
                type: 'bar',
                data: {
                    labels: urlData.map(d => {
                        let u = d.url;
                        try {
                            let parts = u.split('/');
                            return parts[2] || parts[0] || u.substring(0, 20) + '...';
                        } catch (e) { return u.substring(0, 15); }
                    }),
                    datasets: [{
                        label: 'Bloqueios',
                        data: urlData.map(d => d.count),
                        backgroundColor: 'rgba(231, 74, 59, 0.8)',
                        borderRadius: 4
                    }]
                },
                options: commonOptions
            });
        }
    });
</script>
{% endblock %}
"""

# 2. WRITE LOCAL FILE
local_path = r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events\webfilter_v2.html"
with open(local_path, 'w', encoding='utf-8') as f:
    f.write(html_content)
print(f"File updated locally: {local_path}")
