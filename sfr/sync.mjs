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

// 빌드 산출물·외부 체크아웃은 스캔 제외(우리 소스만 대상)
const SKIP = new Set(['node_modules', '.git', 'buildroot', 'output', 'keys']);
async function walk(dir, acc = []) {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name) || e.isSymbolicLink()) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) await walk(p, acc);
    // 텍스트 소스/설정/스크립트 + 확장자 없는 스크립트(S65rtsp-server, fwinfo 등)
    else if (/\.(c|h|mk|sh|conf|rules|txt|cfg|in|md|js|mjs|ya?ml)$/.test(e.name) || !e.name.includes('.')) acc.push(p);
  }
  return acc;
}

const files = await walk(ROOT);
// SFR:<id> 또는 SFR:<id> [STUB] — [STUB]는 태그만 있고 실동작 미구현을 뜻함(정직성 표기)
const tag = /SFR:\s*(\d+\.\d+\.\d+)\s*(\[STUB\])?/g;
const impl = new Map(); // id -> Set(files)  실구현 위치(비-STUB)
const stub = new Map(); // id -> Set(files)  스텁 위치([STUB])
for (const f of files) {
  if (f === SPEC) continue; // 스펙 자신은 제외
  const txt = await readFile(f, 'utf8');
  let m;
  while ((m = tag.exec(txt))) {
    const id = m[1], isStub = !!m[2];
    const map = isStub ? stub : impl;
    if (!map.has(id)) map.set(id, new Set());
    map.get(id).add(f.replace(ROOT + '/', ''));
  }
}

const sfr = JSON.parse(await readFile(join(ROOT, 'sfr', 'sfr-ipcam.json'), 'utf8'));
const items = sfr.items;
// 분류: 해당없음 > 실구현(비-STUB 위치 존재) > 스텁(STUB 위치만) > 미착수
let done = 0, stubN = 0, todo = 0, na = 0;
const rows = items.map(it => {
  const id = it.id;
  let status, where = '';
  if (NA.has(id)) { status = '해당없음'; na++; }
  else if (impl.has(id)) { status = '구현'; where = [...impl.get(id)].join(', '); done++; }
  else if (stub.has(id)) { status = '스텁'; where = [...stub.get(id)].join(', '); stubN++; }
  else { status = '미착수'; todo++; }
  return `| ${id} | ${it.group} | ${it.level} | ${status} | ${where} |`;
});

const table = [
  `<!--AUTO-STATUS: sync.mjs 가 생성. 직접 수정 금지-->`,
  `> 커버리지: 구현 ${done} · 스텁 ${stubN} · 미착수 ${todo} · 해당없음 ${na} (총 ${items.length})`,
  `> ('구현'=실동작 코드/설정+테스트, '스텁'=SFR 태그만 있고 실동작 미구현 — 인증 제출 전 실구현 필요)`,
  ``,
  `| 항목 | 영역 | 강도 | 상태 | 매핑 위치 |`,
  `|------|------|------|------|-----------|`,
  ...rows,
  `<!--/AUTO-STATUS-->`,
].join('\n');

const write = process.argv.includes('--write');
console.log(`구현 ${done} / 스텁 ${stubN} / 미착수 ${todo} / 해당없음 ${na} (총 ${items.length})`);
if (stubN) console.log('스텁:', items.filter(i => !NA.has(i.id) && !impl.has(i.id) && stub.has(i.id)).map(i => i.id).join(', '));
if (todo) console.log('미착수:', items.filter(i => !NA.has(i.id) && !impl.has(i.id) && !stub.has(i.id)).map(i => i.id).join(', '));

if (write) {
  let spec = await readFile(SPEC, 'utf8').catch(() => null);
  if (spec == null) { console.error('스펙 파일 없음:', SPEC); process.exit(1); }
  spec = spec.replace(/<!--AUTO-STATUS[\s\S]*?<!--\/AUTO-STATUS-->/, table);
  await writeFile(SPEC, spec);
  console.log('→ 구현명세서 상태표 갱신됨');
}
