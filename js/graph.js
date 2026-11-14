/**
 * Construit le graphe domaine -> sous-domaines avec Cytoscape.js.
 * Attend deux variables globales définies inline dans organization.php :
 *   window.ROOT_DOMAIN (string)
 *   window.SUBDOMAINS (array de strings)
 */
function renderAttackSurfaceGraph() {
    const rootDomain = window.ROOT_DOMAIN || '';
    const subdomains = window.SUBDOMAINS || [];

    const elements = [
        { data: { id: 'root', label: rootDomain }, classes: 'root' },
        ...subdomains.map((host, i) => ({ data: { id: 'sd' + i, label: host } })),
        ...subdomains.map((host, i) => ({ data: { source: 'root', target: 'sd' + i } })),
    ];

    cytoscape({
        container: document.getElementById('graph'),
        elements: elements,
        style: [
            { selector: 'node', style: {
                'background-color': '#4fd1c5', 'label': 'data(label)',
                'color': '#e2e8f0', 'font-size': '10px', 'text-valign': 'bottom',
                'text-margin-y': 6, 'width': 14, 'height': 14
            }},
            { selector: '.root', style: {
                'background-color': '#f472b6', 'width': 26, 'height': 26, 'font-size': '13px'
            }},
            { selector: 'edge', style: {
                'width': 1, 'line-color': '#2a3655', 'curve-style': 'bezier'
            }},
        ],
        layout: { name: 'concentric', minNodeSpacing: 30 },
    });
}

document.addEventListener('DOMContentLoaded', renderAttackSurfaceGraph);
