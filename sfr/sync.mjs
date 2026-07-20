// sync.mjs — 코드 ↔ 53항목 ↔ 구현명세서 동기화기
//   1) 트리 전체에서 SFR:<항목ID> 태그를 스캔 → 어떤 요구항목이 코드에 매핑됐는지 수집
//   2) sfr-ipcam.json 의 53항목과 대조 → 구현/미구현/미적용 집계
//   3) impl-spec/구현명세서-3장.md 의 <!--AUTO-STATUS--> 블록만 갱신(손으로 쓴 서술은 보존)
// 사용: node sfr/sync.mjs [--write]
import { readFile, writeFile, readdir, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SPEC = join(ROOT, 'impl-spec', '구현명세서-3장.md');
// 제품특성상 미적용(해당사항 없음) 3건
const NA = new Set(['1.3.1', '1.3.2', '8.2.3']);

async function walk(dir, acc = []) {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git') continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) await walk(p, acc);
    // 텍스트 소스/설정/스크립트 + 확장자 없는 스크립트(S65rtsp-server, fwinfo 등)
    else if (/\.(c|h|mk|sh|conf|rules|txt|cfg|in|md|js|mjs|ya?ml)$/.test(e.name) || !e.name.includes('.')) acc.push(p);
  }
  return acc;
}

const files = await walk(ROOT);
const tag = /SFR:\s*(\d+\.\d+\.\d+)/g;
const covered = new Map(); // id -> [files]
for (const f of files) {
  if (f === SPEC) continue; // 스펙 자신은 제외
  const txt = await readFile(f, 'utf8');
  let m;
  while ((m = tag.exec(txt))) {
    const id = m[1];
    if (!covered.has(id)) covered.set(id, new Set());
    covered.get(id).add(f.replace(ROOT + '/', ''));
  }
}

const sfr = JSON.parse(await readFile(join(ROOT, 'sfr', 'sfr-ipcam.json'), 'utf8'));
const items = sfr.items;
let done = 0, todo = 0, na = 0;
const rows = items.map(it => {
  const id = it.id;
  let status, where = '';
  if (NA.has(id)) { status = '해당없음'; na++; }
  else if (covered.has(id)) { status = '매핑됨'; where = [...covered.get(id)].join(', '); done++; }
  else { status = '미착수'; todo++; }
  return `| ${id} | ${it.group} | ${it.level} | ${status} | ${where} |`;
});

const table = [
  `<!--AUTO-STATUS: sync.mjs 가 생성. 직접 수정 금지-->`,
  `> 커버리지: 매핑 ${done} · 미착수 ${todo} · 해당없음 ${na} (총 ${items.length})`,
  ``,
  `| 항목 | 영역 | 강도 | 상태 | 매핑 위치 |`,
  `|------|------|------|------|-----------|`,
  ...rows,
  `<!--/AUTO-STATUS-->`,
].join('\n');

const write = process.argv.includes('--write');
console.log(`매핑 ${done} / 미착수 ${todo} / 해당없음 ${na} (총 ${items.length})`);
if (todo) console.log('미착수:', items.filter(i => !NA.has(i.id) && !covered.has(i.id)).map(i => i.id).join(', '));

if (write) {
  let spec = await readFile(SPEC, 'utf8').catch(() => null);
  if (spec == null) { console.error('스펙 파일 없음:', SPEC); process.exit(1); }
  spec = spec.replace(/<!--AUTO-STATUS[\s\S]*?<!--\/AUTO-STATUS-->/, table);
  await writeFile(SPEC, spec);
  console.log('→ 구현명세서 상태표 갱신됨');
}
