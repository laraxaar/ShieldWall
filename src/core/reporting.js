'use strict';

const fs = require('fs');
const path = require('path');

const DAY_MS = 24 * 60 * 60 * 1000;
const REPORT_14DAYS = 14 * DAY_MS;
// Cap interval at 24 days to avoid Node.js 32-bit setTimeout/setInterval overflow (2147483647ms)
const REPORT_MONTHLY = Math.min(30 * DAY_MS, 2147483647); 

class ReportingEngine {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.reportsDir = options.reportsDir || path.join(process.cwd(), 'reports');
    this.maxStoredReports = options.maxStoredReports || 12;
    this.onReport = options.onReport || null;
    this.logger = options.logger || console;
    
    this._ensureDir();
    this._scheduleReports();
  }

  _ensureDir() {
    if (!fs.existsSync(this.reportsDir)) {
      fs.mkdirSync(this.reportsDir, { recursive: true });
    }
  }

  _scheduleReports() {
    if (!this.enabled) return;
    
    const now = Date.now();
    const next14d = this._getNextReportTime(REPORT_14DAYS);
    const nextMonth = this._getNextReportTime(REPORT_MONTHLY);
    
    setTimeout(() => this._generate14DayReport(), next14d - now);
    setTimeout(() => this._generateMonthlyReport(), nextMonth - now);
    
    setInterval(() => this._generate14DayReport(), REPORT_14DAYS);
    setInterval(() => this._generateMonthlyReport(), REPORT_MONTHLY);
  }

  _getNextReportTime(interval) {
    const now = Date.now();
    return Math.ceil(now / interval) * interval;
  }

  generateReport(history, periodDays, periodName) {
    const cutoff = Date.now() - (periodDays * DAY_MS);
    const events = history.filter(e => new Date(e.timestamp).getTime() > cutoff);
    
    const report = {
      period: periodName,
      generatedAt: new Date().toISOString(),
      periodDays,
      summary: this._generateSummary(events),
      topThreats: this._analyzeTopThreats(events),
      endpoints: this._analyzeEndpoints(events),
      timeline: this._generateTimeline(events, periodDays),
      recommendations: [],
      comparison: null,
    };
    
    report.recommendations = this._generateRecommendations(report);
    report.comparison = this._compareWithPrevious(report, periodName);
    
    return report;
  }

  _generateSummary(events) {
    const attacks = events.filter(e => e.type === 'attack');
    const uniqueIPs = new Set(attacks.map(a => a.ip)).size;
    const blocked = attacks.filter(a => a.action === 'blocked').length;
    
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const byCategory = {};
    const byResponse = {};
    
    for (const a of attacks) {
      bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
      byCategory[a.category] = (byCategory[a.category] || 0) + 1;
      
      const status = a.blocked ? 'blocked (403/429)' : 'detected (logged)';
      byResponse[status] = (byResponse[status] || 0) + 1;
    }
    
    return {
      totalAttacks: attacks.length,
      uniqueAttackers: uniqueIPs,
      blocked,
      detected: attacks.length - blocked,
      blockRate: attacks.length ? ((blocked / attacks.length) * 100).toFixed(1) : 0,
      bySeverity,
      byCategory,
      byResponse,
    };
  }

  _analyzeTopThreats(events) {
    const attacks = events.filter(e => e.type === 'attack');
    const ruleCount = {};
    const ipCount = {};
    const urlCount = {};
    
    for (const a of attacks) {
      ruleCount[a.rule] = (ruleCount[a.rule] || 0) + 1;
      ipCount[a.ip] = (ipCount[a.ip] || 0) + 1;
      urlCount[a.url] = (urlCount[a.url] || 0) + 1;
    }
    
    return {
      topRules: Object.entries(ruleCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([rule, count]) => ({ rule, count })),
      topAttackers: Object.entries(ipCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count })),
      topTargets: Object.entries(urlCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([url, count]) => ({ url, count })),
    };
  }

  _analyzeEndpoints(events) {
    const attacks = events.filter(e => e.type === 'attack');
    const endpointStats = {};
    
    for (const a of attacks) {
      const endpoint = a.url?.split('?')[0] || '/';
      if (!endpointStats[endpoint]) {
        endpointStats[endpoint] = { 
          attacks: 0, 
          uniqueAttackers: new Set(),
          severities: [],
          rules: new Set(),
        };
      }
      endpointStats[endpoint].attacks++;
      endpointStats[endpoint].uniqueAttackers.add(a.ip);
      endpointStats[endpoint].severities.push(a.severity);
      endpointStats[endpoint].rules.add(a.rule);
    }
    
    const endpoints = Object.entries(endpointStats)
      .map(([endpoint, data]) => ({
        endpoint,
        attacks: data.attacks,
        uniqueAttackers: data.uniqueAttackers.size,
        maxSeverity: data.severities.includes('critical') ? 'critical' :
                     data.severities.includes('high') ? 'high' :
                     data.severities.includes('medium') ? 'medium' : 'low',
        ruleTypes: Array.from(data.rules),
      }))
      .sort((a, b) => b.attacks - a.attacks)
      .slice(0, 10);
    
    const criticalEndpoints = endpoints.filter(e => e.maxSeverity === 'critical');
    const highVolumeEndpoints = endpoints.filter(e => e.attacks > endpoints[0]?.attacks * 0.5);
    
    return { all: endpoints, critical: criticalEndpoints, highVolume: highVolumeEndpoints };
  }

  _generateTimeline(events, days) {
    const timeline = {};
    const now = Date.now();
    
    for (let i = 0; i < days; i++) {
      const date = new Date(now - (i * DAY_MS)).toISOString().split('T')[0];
      timeline[date] = { attacks: 0, blocked: 0, uniqueIPs: new Set() };
    }
    
    for (const e of events.filter(e => e.type === 'attack')) {
      const date = e.timestamp?.split('T')[0];
      if (timeline[date]) {
        timeline[date].attacks++;
        if (e.action === 'blocked') timeline[date].blocked++;
        timeline[date].uniqueIPs.add(e.ip);
      }
    }
    
    return Object.entries(timeline)
      .map(([date, data]) => ({
        date,
        attacks: data.attacks,
        blocked: data.blocked,
        uniqueIPs: data.uniqueIPs.size,
      }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }

  // Generates actionable security recommendations based on threat analysis
  // Priorities: critical (immediate action), high (urgent), medium (planned)
  _generateRecommendations(report) {
    const recs = [];
    const { summary, endpoints, topThreats } = report;
    
    // Critical endpoint protection
    if (endpoints.critical.length > 0) {
      const ep = endpoints.critical[0];
      recs.push({
        priority: 'critical',
        area: 'endpoint_protection',
        message: `Strengthen protection for ${ep.endpoint} — ${ep.attacks} attacks, critical threat level`,
        action: 'Add strict rate limiting, input validation, and logging',
      });
    }
    
    // High volume attack pattern
    if (endpoints.highVolume.length > 0 && endpoints.highVolume[0].attacks > 100) {
      const ep = endpoints.highVolume[0];
      recs.push({
        priority: 'high',
        area: 'rate_limiting',
        message: `Endpoint ${ep.endpoint} under intensive attack (${ep.attacks} attempts)`,
        action: 'Reduce rate limits, add CAPTCHA for suspicious IPs',
      });
    }
    
    // Low block rate
    if (summary.blockRate < 80 && summary.totalAttacks > 10) {
      recs.push({
        priority: 'medium',
        area: 'rule_tuning',
        message: `Low block rate (${summary.blockRate}%) — many attacks only being logged`,
        action: 'Switch WAF to block mode for high/critical severity rules',
      });
    }
    
    // Repeated attacks from same IP
    const repeatOffenders = topThreats.topAttackers.filter(a => a.count > 20);
    if (repeatOffenders.length > 0) {
      recs.push({
        priority: 'high',
        area: 'ip_blocking',
        message: `IP ${repeatOffenders[0].ip} attacked ${repeatOffenders[0].count} times`,
        action: 'Add IP to permanent block list or integrate with firewall',
      });
    }
    
    // Specific attack types
    if (summary.byCategory.injection > summary.totalAttacks * 0.3) {
      recs.push({
        priority: 'critical',
        area: 'input_validation',
        message: 'High injection ratio — possible vulnerabilities in data processing',
        action: 'Audit SQL/NoSQL query construction, use parameterized queries',
      });
    }
    
    if (summary.byCategory['path-traversal'] > 10) {
      recs.push({
        priority: 'high',
        area: 'file_access',
        message: 'Numerous path traversal attempts',
        action: 'Check file path sanitization, use allowlists',
      });
    }

    // Vector shift detection (from extended analysis if available)
    if (report.extended?.vectorShift?.recommendation) {
      recs.push({
        priority: 'high',
        area: 'strategy',
        message: report.extended.vectorShift.recommendation,
        action: 'Review protection considering attack vector shifts',
      });
    }

    // Persistent attackers (targeted reconnaissance)
    if (report.extended?.persistentAttackers?.length > 0) {
      const p = report.extended.persistentAttackers[0];
      recs.push({
        priority: 'critical',
        area: 'firewall',
        message: `Targeted reconnaissance: IP ${p.ip} active for ${p.periodsActive} periods using ${p.attackCategories.length} vectors`,
        action: 'Block at network level (iptables/Cloudflare), prevent reaching Node.js',
      });
    }

    return recs;
  }

  // Compares current report with previous same-type report to identify trends
  // Returns null if no previous report exists for comparison
  _compareWithPrevious(currentReport, periodType) {
    const reports = this._loadStoredReports()
      .filter(r => r.period === periodType)
      .sort((a, b) => new Date(b.generatedAt) - new Date(a.generatedAt));
    
    if (reports.length < 2) return null;
    
    const previous = reports[1]; // [0] is current (just saved), [1] is previous
    const curr = currentReport.summary;
    const prev = previous.summary;
    
    // Calculate percentage change, handling division by zero
    const change = (curr, prev) => {
      if (prev === 0) return curr > 0 ? '+∞' : '0%';
      const pct = ((curr - prev) / prev * 100).toFixed(1);
      return (pct > 0 ? '+' : '') + pct + '%';
    };
    
    return {
      attacksChange: change(curr.totalAttacks, prev.totalAttacks),
      attackersChange: change(curr.uniqueAttackers, prev.uniqueAttackers),
      blockRateChange: (curr.blockRate - prev.blockRate).toFixed(1),
      trend: curr.totalAttacks > prev.totalAttacks * 1.2 ? 'increasing' :
             curr.totalAttacks < prev.totalAttacks * 0.8 ? 'decreasing' : 'stable',
    };
  }

  _loadStoredReports() {
    try {
      const files = fs.readdirSync(this.reportsDir)
        .filter(f => f.endsWith('.json'))
        .map(f => {
          try {
            return JSON.parse(fs.readFileSync(path.join(this.reportsDir, f), 'utf8'));
          } catch { return null; }
        })
        .filter(Boolean);
      return files;
    } catch {
      return [];
    }
  }

  _saveReport(report) {
    const filename = `report-${report.period}-${report.generatedAt.split('T')[0]}.json`;
    const filepath = path.join(this.reportsDir, filename);
    fs.writeFileSync(filepath, JSON.stringify(report, null, 2));
    
    this._cleanupOldReports();
    return filepath;
  }

  _cleanupOldReports() {
    const files = fs.readdirSync(this.reportsDir)
      .filter(f => f.endsWith('.json'))
      .map(f => ({
        name: f,
        path: path.join(this.reportsDir, f),
        mtime: fs.statSync(path.join(this.reportsDir, f)).mtime,
      }))
      .sort((a, b) => b.mtime - a.mtime);
    
    if (files.length > this.maxStoredReports) {
      for (const f of files.slice(this.maxStoredReports)) {
        fs.unlinkSync(f.path);
      }
    }
  }

  _generate14DayReport() {
    this.logger.info('Generating 14-day report...');
    
    // Get history from logger if available
    const history = this.logger?.history || [];
    const report = this.generateReport(history, 14, '14d');
    
    const filepath = this._saveReport(report);
    
    if (this.onReport) {
      this.onReport({ type: '14d', report, filepath });
    }
    
    return report;
  }

  _generateMonthlyReport() {
    this.logger.info('Generating monthly report...');
    
    const history = this.logger?.history || [];
    const report = this.generateReport(history, 30, 'monthly');

    // Add extended analysis for monthly (before recommendations so they can use this data)
    report.extended = {
      attackEvolution: this._analyzeEvolution(history, 30),
      newAttackPatterns: this._detectNewPatterns(history, 30),
      geographicDistribution: this._analyzeGeo(history),
      vectorShift: this._analyzeVectorShift(history, 30),
      persistentAttackers: this._findPersistentAttackers(history, 30),
      roi: this._calculateROI(history),
      chartSVG: this.generateSVGChart(report.timeline),
    };

    // Regenerate recommendations with extended data
    report.recommendations = this._generateRecommendations(report);
    
    const filepath = this._saveReport(report);
    
    if (this.onReport) {
      this.onReport({ type: 'monthly', report, filepath });
    }
    
    return report;
  }

  // Analyzes attack volume change between first and second half of period
  // Trend thresholds: >30% increase = accelerating, >30% decrease = decelerating
  _analyzeEvolution(history, days) {
    const week1 = history.filter(e => {
      const d = new Date(e.timestamp).getTime();
      return d > Date.now() - (days * DAY_MS) && d < Date.now() - (days/2 * DAY_MS);
    });
    const week2 = history.filter(e => {
      const d = new Date(e.timestamp).getTime();
      return d > Date.now() - (days/2 * DAY_MS);
    });
    
    return {
      firstHalf: week1.filter(e => e.type === 'attack').length,
      secondHalf: week2.filter(e => e.type === 'attack').length,
      trend: week2.length > week1.length * 1.3 ? 'accelerating' :
             week2.length < week1.length * 0.7 ? 'decelerating' : 'stable',
    };
  }

  // Detects attack types that appear in recent period but were absent in previous period
  // Helps identify emerging threats and new attack vectors
  _detectNewPatterns(history, days) {
    const recent = history.filter(e => 
      new Date(e.timestamp).getTime() > Date.now() - (days * DAY_MS)
    );
    const older = history.filter(e => 
      new Date(e.timestamp).getTime() < Date.now() - (days * DAY_MS) &&
      new Date(e.timestamp).getTime() > Date.now() - (days * 2 * DAY_MS)
    );
    
    // Compare rule sets between periods to find new attack patterns
    const recentRules = new Set(recent.filter(e => e.type === 'attack').map(e => e.rule));
    const oldRules = new Set(older.filter(e => e.type === 'attack').map(e => e.rule));
    
    const newPatterns = Array.from(recentRules).filter(r => !oldRules.has(r));
    
    return newPatterns.map(rule => ({
      rule,
      count: recent.filter(e => e.rule === rule).length,
      firstSeen: recent.find(e => e.rule === rule)?.timestamp,
    }));
  }

  _analyzeGeo(history) {
    const byCountry = {};
    for (const e of history.filter(e => e.type === 'attack')) {
      const country = e.data?.geoip?.country || 'unknown';
      byCountry[country] = (byCountry[country] || 0) + 1;
    }
    return Object.entries(byCountry)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([country, count]) => ({ country, count }));
  }

  generateManualReport(history, days, name) {
    return this.generateReport(history, days, name || `custom-${days}d`);
  }

  getStoredReports() {
    return this._loadStoredReports();
  }

  // Tracks migration of attackers between attack vectors (e.g., cmdi → api-abuse)
  // Identifies strategic shifts in attacker behavior across reporting periods
  _analyzeVectorShift(history, days) {
    const reports = this._loadStoredReports().slice(0, 3);
    if (reports.length < 2) return null;

    const curr = reports[0];
    const prev = reports[1];

    const currCats = curr.summary?.byCategory || {};
    const prevCats = prev.summary?.byCategory || {};

    const shifts = [];
    for (const [cat, currCount] of Object.entries(currCats)) {
      const prevCount = prevCats[cat] || 0;
      if (currCount > prevCount * 1.5) {
        shifts.push({ category: cat, direction: 'increasing', change: `${((currCount - prevCount) / Math.max(prevCount, 1) * 100).toFixed(0)}%` });
      } else if (currCount < prevCount * 0.5 && prevCount > 10) {
        shifts.push({ category: cat, direction: 'decreasing', change: `${((prevCount - currCount) / prevCount * 100).toFixed(0)}%` });
      }
    }

    return {
      shifts,
      recommendation: shifts.some(s => s.category === 'api' || s.category === 'injection')
        ? 'Attack vector shifted to API layer. Review rate limits and input validation on REST/GraphQL endpoints.'
        : null,
    };
  }

  // Identifies IPs that persist across multiple periods using different attack modules
  // Flags targeted reconnaissance vs opportunistic scanning
  _findPersistentAttackers(history, days) {
    const reports = this._loadStoredReports();
    if (reports.length < 2) return [];

    const ipSignatures = new Map();

    for (const report of reports.slice(0, 3)) {
      const topAttackers = report.topThreats?.topAttackers || [];
      for (const { ip, count } of topAttackers) {
        if (!ipSignatures.has(ip)) ipSignatures.set(ip, { periods: 0, categories: new Set(), totalAttacks: 0 });
        const data = ipSignatures.get(ip);
        data.periods++;
        data.totalAttacks += count;
        if (report.summary?.byCategory) {
          for (const cat of Object.keys(report.summary.byCategory)) data.categories.add(cat);
        }
      }
    }

    const persistent = [];
    for (const [ip, data] of ipSignatures) {
      if (data.periods >= 2 && data.categories.size >= 2) {
        persistent.push({
          ip,
          periodsActive: data.periods,
          attackCategories: Array.from(data.categories),
          totalAttacks: data.totalAttacks,
          threatLevel: data.periods >= 3 ? 'critical' : 'high',
          action: 'Add to permanent firewall block list (iptables/Cloudflare)',
        });
      }
    }

    return persistent.sort((a, b) => b.totalAttacks - a.totalAttacks).slice(0, 5);
  }

  // Calculates resource savings from blocking malicious traffic
  // Estimates bandwidth and CPU time saved by WAF interception
  _calculateROI(events) {
    const blocked = events.filter(e => e.type === 'attack' && e.action === 'blocked');
    const avgRequestSize = 2048; // 2KB average
    const avgProcessingTime = 50; // 50ms saved by not hitting app layer

    const blockedCount = blocked.length;
    const trafficSaved = (blockedCount * avgRequestSize) / (1024 * 1024 * 1024); // GB
    const cpuTimeSaved = (blockedCount * avgProcessingTime) / (1000 * 60 * 60); // hours

    return {
      blockedRequests: blockedCount,
      trafficSavedGB: trafficSaved.toFixed(2),
      cpuTimeSavedHours: cpuTimeSaved.toFixed(2),
      estimatedCostSaved: `$${(trafficSaved * 0.09 + cpuTimeSaved * 0.05).toFixed(2)}`, // AWS pricing approx
    };
  }

  // Generates lightweight SVG bar chart for timeline visualization
  // No external dependencies — pure string concatenation
  generateSVGChart(timeline, width = 600, height = 200) {
    if (!timeline?.length) return '';

    const maxVal = Math.max(...timeline.map(d => d.attacks), 1);
    const barWidth = (width - 60) / timeline.length;
    const scale = (height - 40) / maxVal;

    let bars = '';
    for (let i = 0; i < timeline.length; i++) {
      const day = timeline[i];
      const barHeight = day.attacks * scale;
      const x = 40 + i * barWidth;
      const y = height - 20 - barHeight;
      const color = day.attacks > maxVal * 0.7 ? '#ef4444' : day.attacks > maxVal * 0.3 ? '#f59e0b' : '#22c55e';
      bars += `<rect x="${x}" y="${y}" width="${barWidth - 2}" height="${barHeight}" fill="${color}" rx="2"/>`;
    }

    return `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">
      <text x="20" y="15" font-size="12" fill="#666">Attacks</text>
      <line x1="35" y1="20" x2="35" y2="${height - 20}" stroke="#ddd"/>
      <line x1="35" y1="${height - 20}" x2="${width - 20}" y2="${height - 20}" stroke="#ddd"/>
      ${bars}
      <text x="${width / 2}" y="${height - 5}" font-size="10" fill="#999" text-anchor="middle">Timeline</text>
    </svg>`;
  }
}

module.exports = ReportingEngine;
