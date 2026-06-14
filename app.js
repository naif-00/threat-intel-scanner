let currentType = 'url';
let apiKey = localStorage.getItem('vt_api_key') || '';
let lastReportData = null; // يحفظ آخر نتيجة فحص لاستخدامها في تصدير PDF


window.addEventListener('DOMContentLoaded', () => {
  if (apiKey) {
    document.getElementById('apiKeyInput').value = apiKey;
    document.getElementById('apiStatus').innerHTML = '✅ API Key محفوظ — جاهز للفحص';
    document.getElementById('apiStatus').style.color = 'var(--safe)';
  }

  
  setInterval(() => {
    const now = new Date();
    document.getElementById('current-time').textContent =
      now.toUTCString().split(' ')[4] + ' UTC';
  }, 1000);
});


function saveApiKey() {
  const key = document.getElementById('apiKeyInput').value.trim();
  if (!key) return;
  apiKey = key;
  localStorage.setItem('vt_api_key', key);
  document.getElementById('apiStatus').innerHTML = '✅ تم حفظ API Key بنجاح!';
  document.getElementById('apiStatus').style.color = 'var(--safe)';
}


function setType(type) {
  currentType = type;
  ['url', 'hash', 'ip', 'domain'].forEach(t => {
    document.getElementById('btn-' + t).classList.remove('active');
  });
  document.getElementById('btn-' + type).classList.add('active');
  document.getElementById('inputBadge').textContent = type.toUpperCase();

  const placeholders = {
    url:    'https://suspicious-site.com/malware.exe',
    hash:   'MD5 / SHA1 / SHA256 hash of a file',
    ip:     '192.168.1.1',
    domain: 'suspicious-domain.com'
  };
  document.getElementById('targetInput').placeholder = placeholders[type];
}


function setExample(type, value) {
  setType(type);
  document.getElementById('targetInput').value = value;
}


function showLoading(steps) {
  document.getElementById('loadingPanel').classList.add('active');
  document.getElementById('resultsPanel').classList.remove('active');
  document.getElementById('errorPanel').classList.remove('active');

  const stepsEl = document.getElementById('loadingSteps');
  stepsEl.innerHTML = steps.map((s, i) =>
    `<div class="loading-step ${i === 0 ? 'step-active' : ''}" id="step-${i}">
      <span>${i === 0 ? '▶' : '○'}</span> ${s}
    </div>`
  ).join('');
}


function updateStep(index, total) {
  for (let i = 0; i < total; i++) {
    const el = document.getElementById('step-' + i);
    if (!el) continue;
    if (i < index) {
      el.className = 'loading-step step-done';
      el.querySelector('span').textContent = '✓';
    } else if (i === index) {
      el.className = 'loading-step step-active';
      el.querySelector('span').textContent = '▶';
    }
  }
}


function showError(msg) {
  document.getElementById('loadingPanel').classList.remove('active');
  const el = document.getElementById('errorPanel');
  el.textContent = '⛔ ERROR: ' + msg;
  el.classList.add('active');
}


// ───────────────────────────────────────────────
// 🌍 تحويل كود الدولة (مثل SA, US) إلى علم Emoji
// ───────────────────────────────────────────────
function countryCodeToFlag(countryCode) {
  if (!countryCode || countryCode.length !== 2) return '🏳️';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map(char => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

// خريطة أسماء الدول بالعربي (الأكثر شيوعاً) — fallback للإنجليزي لو غير موجود
const COUNTRY_NAMES_AR = {
  US: 'الولايات المتحدة', GB: 'المملكة المتحدة', SA: 'السعودية', AE: 'الإمارات',
  EG: 'مصر', DE: 'ألمانيا', FR: 'فرنسا', RU: 'روسيا', CN: 'الصين', JP: 'اليابان',
  KR: 'كوريا الجنوبية', NL: 'هولندا', CA: 'كندا', AU: 'أستراليا', IN: 'الهند',
  BR: 'البرازيل', IT: 'إيطاليا', ES: 'إسبانيا', TR: 'تركيا', SE: 'السويد',
  CH: 'سويسرا', SG: 'سنغافورة', UA: 'أوكرانيا', PL: 'بولندا', IE: 'أيرلندا',
  KW: 'الكويت', QA: 'قطر', BH: 'البحرين', OM: 'عُمان', JO: 'الأردن', IQ: 'العراق'
};

function getCountryName(code) {
  if (!code) return '—';
  return COUNTRY_NAMES_AR[code.toUpperCase()] || code.toUpperCase();
}

// خريطة أسماء الدول بالإنجليزي — تستخدم في تقرير PDF لتجنب مشاكل عرض العربية
const COUNTRY_NAMES_EN = {
  US: 'United States', GB: 'United Kingdom', SA: 'Saudi Arabia', AE: 'United Arab Emirates',
  EG: 'Egypt', DE: 'Germany', FR: 'France', RU: 'Russia', CN: 'China', JP: 'Japan',
  KR: 'South Korea', NL: 'Netherlands', CA: 'Canada', AU: 'Australia', IN: 'India',
  BR: 'Brazil', IT: 'Italy', ES: 'Spain', TR: 'Turkey', SE: 'Sweden',
  CH: 'Switzerland', SG: 'Singapore', UA: 'Ukraine', PL: 'Poland', IE: 'Ireland',
  KW: 'Kuwait', QA: 'Qatar', BH: 'Bahrain', OM: 'Oman', JO: 'Jordan', IQ: 'Iraq'
};

function getCountryNameEn(code) {
  if (!code) return '—';
  return COUNTRY_NAMES_EN[code.toUpperCase()] || code.toUpperCase();
}


async function scan() {
  const target = document.getElementById('targetInput').value.trim();
  if (!target) return showError('يرجى إدخال هدف للفحص');
  if (!apiKey) return showError('API Key مطلوب. أدخله في حقل API Config أعلى وانقر حفظ.');

  document.getElementById('scanBtn').disabled = true;

  const steps = [
    'جارٍ إعداد الطلب...',
    'الاتصال بـ VirusTotal API...',
    'انتظار نتائج محركات الفحص...',
    'تحليل وتجميع التقرير...'
  ];

  showLoading(steps);

  try {
    let endpoint  = '';
    let resourceId = '';

    if (currentType === 'url') {
      await new Promise(r => setTimeout(r, 500));
      updateStep(1, steps.length);
      const urlId = btoa(target).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
      endpoint   = `https://www.virustotal.com/api/v3/urls/${urlId}`;
      resourceId = urlId;

    } else if (currentType === 'hash') {
      endpoint   = `https://www.virustotal.com/api/v3/files/${target}`;
      resourceId = target;

    } else if (currentType === 'ip') {
      endpoint   = `https://www.virustotal.com/api/v3/ip_addresses/${target}`;
      resourceId = target;

    } else if (currentType === 'domain') {
      endpoint   = `https://www.virustotal.com/api/v3/domains/${target}`;
      resourceId = target;
    }

    await new Promise(r => setTimeout(r, 800));
    updateStep(2, steps.length);

    const response = await fetch(endpoint, {
      headers: {
        'x-apikey': apiKey,
        'Accept':   'application/json'
      }
    });

    if (!response.ok) {
      if (response.status === 404) throw new Error('الهدف غير موجود في قاعدة بيانات VirusTotal.');
      if (response.status === 401) throw new Error('API Key غير صحيح أو منتهي الصلاحية.');
      if (response.status === 429) throw new Error('تجاوزت حد الطلبات. انتظر دقيقة وحاول مجدداً.');
      throw new Error(`HTTP ${response.status} — خطأ من الخادم`);
    }

    const data = await response.json();
    updateStep(3, steps.length);

    await new Promise(r => setTimeout(r, 600));
    renderResults(data, target, resourceId);

  } catch (err) {
    showError(err.message);
  } finally {
    document.getElementById('scanBtn').disabled = false;
  }
}


function renderResults(data, originalTarget, resourceId) {
  document.getElementById('loadingPanel').classList.remove('active');
  document.getElementById('resultsPanel').classList.add('active');

  const attrs   = data.data?.attributes || {};
  const stats   = attrs.last_analysis_stats   || {};
  const results = attrs.last_analysis_results || {};

  const malicious  = stats.malicious  || 0;
  const suspicious = stats.suspicious || 0;
  const undetected = stats.undetected || 0;
  const harmless   = stats.harmless   || 0;
  const total      = malicious + suspicious + undetected + harmless + (stats.failure || 0);

  // ── الحكم ──
  const banner      = document.getElementById('verdictBanner');
  const threatScore = total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0;

  let verdictLabel = 'CLEAN';

  if (malicious > 3) {
    banner.className = 'verdict-banner danger';
    document.getElementById('verdictIcon').textContent  = '🚨';
    document.getElementById('verdictTitle').textContent = 'MALICIOUS';
    document.getElementById('verdictTitle').style.color = 'var(--danger)';
    document.getElementById('verdictSub').textContent   = `تم اكتشافه كخطر بواسطة ${malicious} محرك فحص`;
    document.getElementById('threatFill').style.background = 'var(--danger)';
    verdictLabel = 'MALICIOUS';
  } else if (malicious > 0 || suspicious > 0) {
    banner.className = 'verdict-banner unknown';
    document.getElementById('verdictIcon').textContent  = '⚠️';
    document.getElementById('verdictTitle').textContent = 'SUSPICIOUS';
    document.getElementById('verdictTitle').style.color = 'var(--unknown)';
    document.getElementById('verdictSub').textContent   = `مشبوه — ${malicious + suspicious} إشارة تحذيرية`;
    document.getElementById('threatFill').style.background = 'var(--unknown)';
    verdictLabel = 'SUSPICIOUS';
  } else {
    banner.className = 'verdict-banner safe';
    document.getElementById('verdictIcon').textContent  = '✅';
    document.getElementById('verdictTitle').textContent = 'CLEAN';
    document.getElementById('verdictTitle').style.color = 'var(--safe)';
    document.getElementById('verdictSub').textContent   = 'لم يتم اكتشاف أي تهديدات';
    document.getElementById('threatFill').style.background = 'var(--safe)';
    verdictLabel = 'CLEAN';
  }

  document.getElementById('scoreNum').textContent  = threatScore + '%';
  document.getElementById('scoreNum').style.color  =
    malicious > 3 ? 'var(--danger)' : malicious > 0 ? 'var(--unknown)' : 'var(--safe)';
  setTimeout(() => {
    document.getElementById('threatFill').style.width = threatScore + '%';
  }, 300);

  
  document.getElementById('statMalicious').textContent  = malicious;
  document.getElementById('statSuspicious').textContent = suspicious;
  document.getElementById('statClean').textContent      = undetected + harmless;
  document.getElementById('statTotal').textContent      = total;

  
  const grid = document.getElementById('detectionGrid');
  grid.innerHTML = '';

  const sortedEngines = Object.entries(results).sort((a, b) => {
    const order = { malicious: 0, suspicious: 1, undetected: 2, harmless: 3 };
    return (order[a[1].category] || 4) - (order[b[1].category] || 4);
  });

  sortedEngines.slice(0, 30).forEach(([engine, result]) => {
    const cat  = result.category;
    const item = document.createElement('div');
    item.className = 'detection-item';
    item.innerHTML = `
      <div class="det-indicator ${cat}"></div>
      <div class="det-engine">${engine}</div>
      <div class="det-result ${cat}">${result.result || cat}</div>
    `;
    grid.appendChild(item);
  });

  if (sortedEngines.length === 0) {
    grid.innerHTML = '<div style="color:var(--dim);font-family:Share Tech Mono,monospace;font-size:12px;text-align:center;padding:20px;">لا توجد بيانات محركات فحص متاحة</div>';
  }

  
  const metaGrid  = document.getElementById('metaGrid');
  const metaItems = [];

  metaItems.push({ label: 'TARGET', value: originalTarget.length > 50 ? originalTarget.slice(0, 50) + '...' : originalTarget });
  if (attrs.type_description) metaItems.push({ label: 'FILE TYPE',   value: attrs.type_description });
  if (attrs.size)             metaItems.push({ label: 'SIZE',        value: formatBytes(attrs.size) });
  if (attrs.md5)              metaItems.push({ label: 'MD5',         value: attrs.md5 });
  if (attrs.sha256)           metaItems.push({ label: 'SHA256',      value: attrs.sha256.slice(0, 32) + '...' });
  if (attrs.last_analysis_date) metaItems.push({ label: 'LAST SCAN', value: new Date(attrs.last_analysis_date * 1000).toLocaleDateString('ar') });

  // ───────────────────────────────────────────────
  // 🌍 إضافة: الموقع الجغرافي + علم الدولة
  // ───────────────────────────────────────────────
  let countryDisplay = null;
  if (attrs.country) {
    const flag = countryCodeToFlag(attrs.country);
    const name = getCountryName(attrs.country);
    countryDisplay = `${flag} ${name} (${attrs.country.toUpperCase()})`;
    metaItems.push({ label: 'COUNTRY / الدولة', value: countryDisplay });
  }

  if (attrs.continent) metaItems.push({ label: 'CONTINENT', value: attrs.continent });
  if (attrs.asn)       metaItems.push({ label: 'ASN', value: attrs.asn });
  if (attrs.as_owner)  metaItems.push({ label: 'ISP / OWNER', value: attrs.as_owner });
  if (attrs.network)   metaItems.push({ label: 'NETWORK RANGE', value: attrs.network });

  if (attrs.url)   metaItems.push({ label: 'FINAL URL',   value: attrs.url.slice(0, 50) });
  if (attrs.title) metaItems.push({ label: 'PAGE TITLE',  value: attrs.title });

  metaGrid.innerHTML = metaItems.map(m => `
    <div class="meta-item">
      <div class="meta-label">${m.label}</div>
      <div class="meta-value">${m.value || '—'}</div>
    </div>
  `).join('');

  
  const typeMap = { url: 'url', hash: 'file', ip: 'ip-address', domain: 'domain' };
  document.getElementById('vtLink').href =
    `https://www.virustotal.com/gui/${typeMap[currentType]}/${resourceId}`;

  // ───────────────────────────────────────────────
  // 📄 حفظ بيانات التقرير لاستخدامها عند تصدير PDF
  // ───────────────────────────────────────────────
  lastReportData = {
    target: originalTarget,
    type: currentType,
    verdict: verdictLabel,
    threatScore: threatScore,
    malicious: malicious,
    suspicious: suspicious,
    undetected: undetected,
    harmless: harmless,
    total: total,
    country: countryDisplay,
    countryCode: attrs.country || null,
    countryName: attrs.country ? getCountryName(attrs.country) : null,
    asOwner: attrs.as_owner || null,
    vtLink: document.getElementById('vtLink').href,
    topEngines: sortedEngines.slice(0, 10).map(([engine, result]) => ({
      engine, category: result.category, result: result.result || result.category
    })),
    scanDate: new Date().toISOString().slice(0, 19).replace('T', ' ') + ' UTC'
  };

  // إظهار زر التحميل بعد توفر النتائج
  const downloadBtn = document.getElementById('downloadReportBtn');
  if (downloadBtn) downloadBtn.style.display = 'flex';
}

function formatBytes(bytes) {
  if (bytes < 1024)    return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}


// ───────────────────────────────────────────────
// 📄 إضافة: تصدير تقرير PDF
// ───────────────────────────────────────────────
function downloadPDFReport() {
  if (!lastReportData) return;
  const r = lastReportData;

  const { jsPDF } = window.jspdf;
  const doc = new jsPDF();

  // ألوان الحكم
  const verdictColors = {
    MALICIOUS:  [255, 51, 102],
    SUSPICIOUS: [255, 170, 0],
    CLEAN:      [0, 255, 136]
  };
  const color = verdictColors[r.verdict] || [0, 255, 136];

  // ── العنوان ──
  doc.setFillColor(7, 11, 15);
  doc.rect(0, 0, 210, 297, 'F');

  doc.setTextColor(0, 255, 136);
  doc.setFont('courier', 'bold');
  doc.setFontSize(20);
  doc.text('THREAT INTEL REPORT', 105, 20, { align: 'center' });

  doc.setFontSize(10);
  doc.setTextColor(150, 150, 150);
  doc.text('Powered by VirusTotal API v3', 105, 27, { align: 'center' });
  doc.text(r.scanDate, 105, 33, { align: 'center' });

  // خط فاصل
  doc.setDrawColor(0, 255, 136);
  doc.line(15, 38, 195, 38);

  // ── معلومات الهدف ──
  let y = 50;
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(11);
  doc.setFont('courier', 'normal');

  doc.text(`TARGET: ${r.target}`, 15, y); y += 8;
  doc.text(`TYPE: ${r.type.toUpperCase()}`, 15, y); y += 8;

  if (r.countryCode) {
    doc.text(`LOCATION: ${getCountryNameEn(r.countryCode)} (${r.countryCode.toUpperCase()})`, 15, y); y += 8;
  }
  if (r.asOwner) {
    doc.text(`ISP/OWNER: ${r.asOwner}`, 15, y); y += 8;
  }

  y += 5;

  // ── الحكم (Verdict Box) ──
  doc.setFillColor(color[0], color[1], color[2]);
  doc.setDrawColor(color[0], color[1], color[2]);
  doc.rect(15, y, 180, 22, 'S');

  doc.setTextColor(color[0], color[1], color[2]);
  doc.setFontSize(16);
  doc.setFont('courier', 'bold');
  doc.text(`VERDICT: ${r.verdict}`, 20, y + 10);

  doc.setFontSize(12);
  doc.text(`THREAT SCORE: ${r.threatScore}%`, 20, y + 18);

  y += 32;

  // ── الإحصائيات ──
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(11);
  doc.setFont('courier', 'bold');
  doc.text('SCAN STATISTICS', 15, y);
  y += 8;

  doc.setFont('courier', 'normal');
  doc.setFontSize(10);
  doc.text(`Malicious Engines:   ${r.malicious}`, 15, y); y += 6;
  doc.text(`Suspicious Engines:  ${r.suspicious}`, 15, y); y += 6;
  doc.text(`Undetected/Clean:    ${r.undetected + r.harmless}`, 15, y); y += 6;
  doc.text(`Total Engines:       ${r.total}`, 15, y); y += 12;

  // ── أهم نتائج المحركات ──
  if (r.topEngines.length > 0) {
    doc.setFont('courier', 'bold');
    doc.text('TOP DETECTION ENGINES', 15, y);
    y += 8;

    doc.setFont('courier', 'normal');
    doc.setFontSize(9);

    r.topEngines.forEach(e => {
      if (y > 270) { doc.addPage(); doc.setFillColor(7,11,15); doc.rect(0,0,210,297,'F'); y = 20; doc.setTextColor(255,255,255); }

      const catColors = {
        malicious:  [255, 51, 102],
        suspicious: [255, 170, 0],
        harmless:   [0, 255, 136],
        undetected: [120, 120, 120]
      };
      const c = catColors[e.category] || [200, 200, 200];
      doc.setTextColor(c[0], c[1], c[2]);
      doc.text(`${e.engine}: ${e.result}`, 18, y);
      y += 6;
    });
    y += 8;
  }

  // ── رابط VirusTotal ──
  doc.setTextColor(0, 170, 255);
  doc.setFontSize(9);
  doc.textWithLink('(View Full Report on VirusTotal)', 15, y, { url: r.vtLink });

  // ── Footer ──
  doc.setTextColor(100, 100, 100);
  doc.setFontSize(8);
  doc.text('THREAT INTEL TOOL — For security research purposes only', 105, 290, { align: 'center' });

  // اسم الملف
  const safeTarget = r.target.replace(/[^a-zA-Z0-9]/g, '_').slice(0, 30);
  doc.save(`threat_report_${safeTarget}.pdf`);
}