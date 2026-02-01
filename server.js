const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const PORT = 3847;

function fetchJSON(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const options = {
      hostname: u.hostname,
      path: u.pathname + u.search,
      method: opts.method || 'GET',
      headers: { 'User-Agent': 'ThreatPulse/1.0', ...(opts.headers || {}) },
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch (e) { reject(new Error('Parse error')); }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('Timeout')); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

async function getNVD() {
  const now = new Date();
  const weekAgo = new Date(now - 7 * 86400000).toISOString().replace(/\.\d+Z/, '.000');
  const data = await fetchJSON('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15&pubStartDate=' + weekAgo + '&pubEndDate=' + now.toISOString().replace(/\.\d+Z/, '.000'));
  return (data.vulnerabilities || []).map(v => {
    const cve = v.cve || {};
    const metrics = cve.metrics || {};
    const cvss31 = (metrics.cvssMetricV31 || [])[0];
    const cvss2 = (metrics.cvssMetricV2 || [])[0];
    const score = cvss31?.cvssData?.baseScore || cvss2?.cvssData?.baseScore || 0;
    const sev = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
    const desc = ((cve.descriptions || []).find(d => d.lang === 'en') || {}).value || '';
    return {
      id: cve.id,
      title: cve.id + ' (CVSS ' + score + ')',
      description: desc.slice(0, 300),
      severity: sev,
      source: 'nvd',
      sourceName: 'NVD',
      category: 'CVE',
      date: cve.published || new Date().toISOString(),
      link: 'https://nvd.nist.gov/vuln/detail/' + cve.id,
      ioc: cve.id,
      tags: (cve.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(Boolean),
      score,
    };
  });
}

async function getURLhaus() {
  const data = await fetchJSON('https://urlhaus.abuse.ch/downloads/json_recent/');
  const entries = Object.entries(data).slice(0, 15);
  return entries.map(([id, arr]) => {
    const u = arr[0];
    const threat = (u.threat || 'malware_download').replace(/_/g, ' ');
    const tags = u.tags || [];
    const sev = tags.some(t => /ransomware|botnet/i.test(t)) ? 'critical'
              : tags.some(t => /trojan|rat/i.test(t)) ? 'high'
              : u.threat === 'malware_download' ? 'high' : 'medium';
    return {
      id: 'UH-' + id,
      title: 'Malicious URL: ' + threat,
      description: 'URL: ' + (u.url || '?') + '. Tags: ' + (tags.join(', ') || 'none') + '. Status: ' + (u.url_status || '?'),
      severity: sev,
      source: 'urlhaus',
      sourceName: 'URLhaus',
      category: 'Malicious URL',
      date: u.dateadded || new Date().toISOString(),
      link: u.urlhaus_link || 'https://urlhaus.abuse.ch',
      ioc: u.url || '',
      tags,
    };
  });
}

async function getThreatFox() {
  const data = await fetchJSON('https://threatfox.abuse.ch/export/json/recent/');
  const entries = Object.entries(data).slice(0, 15);
  return entries.map(([id, arr]) => {
    const ioc = arr[0];
    const confidence = ioc.confidence_level || 0;
    const sev = confidence >= 90 ? 'critical' : confidence >= 70 ? 'high' : confidence >= 40 ? 'medium' : 'low';
    const malware = ioc.malware_printable || ioc.malware || 'Unknown';
    const tags = ioc.tags ? ioc.tags.split(',').map(t => t.trim()) : [];
    return {
      id: 'TF-' + id,
      title: malware + ' — ' + (ioc.ioc_type || 'IOC'),
      description: 'Threat: ' + (ioc.threat_type || '?') + '. Malware: ' + malware + '. Confidence: ' + confidence + '%',
      severity: sev,
      source: 'threatfox',
      sourceName: 'ThreatFox',
      category: ioc.threat_type || 'IOC',
      date: ioc.first_seen_utc || new Date().toISOString(),
      link: 'https://threatfox.abuse.ch/ioc/' + id,
      ioc: ioc.ioc_value || '',
      tags,
      confidence,
    };
  });
}

async function getGitHubAdvisories() {
  const data = await fetchJSON('https://api.github.com/advisories?per_page=15&type=reviewed');
  if (!Array.isArray(data)) return [];
  return data.map(adv => ({
    id: adv.cve_id || adv.ghsa_id,
    title: adv.summary || adv.ghsa_id,
    description: (adv.description || '').slice(0, 300),
    severity: adv.severity || 'medium',
    source: 'github',
    sourceName: 'GitHub Advisory',
    category: 'Security Advisory',
    date: adv.published_at || adv.updated_at || new Date().toISOString(),
    link: adv.html_url || 'https://github.com/advisories/' + adv.ghsa_id,
    ioc: adv.cve_id || adv.ghsa_id,
    tags: (adv.identifiers || []).map(i => i.value).filter(Boolean),
  }));
}

const server = http.createServer(async (req, res) => {
  if (req.url === '/api/threats') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    const results = { nvd: [], urlhaus: [], threatfox: [], github: [], errors: [] };
    const fetchers = [
      ['nvd', getNVD],
      ['urlhaus', getURLhaus],
      ['threatfox', getThreatFox],
      ['github', getGitHubAdvisories],
    ];
    await Promise.all(fetchers.map(async ([key, fn]) => {
      try { results[key] = await fn(); }
      catch (e) { results.errors.push({ source: key, message: e.message }); }
    }));
    res.end(JSON.stringify(results));
  } else {
    // Serve index.html
    const file = path.join(__dirname, 'index.html');
    fs.readFile(file, (err, data) => {
      if (err) { res.writeHead(500); res.end('Error'); return; }
      res.setHeader('Content-Type', 'text/html');
      res.end(data);
    });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`ThreatPulse running at http://localhost:${PORT}`);
});
