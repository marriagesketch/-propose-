/* ============================================================
   プロポーズプラン – app.js（自動ペア判定方式）
   ------------------------------------------------------------
   ・ユーザーは暗号キーの入力も個別リンクの受け渡しも一切行わない。
   ・サーバーに送るのは ownerHash（LINE userIdのSHA-256）だけ。
   ・propose_code.gs が毎回 Partners中央API に ownerHash を問い合わせ、
     「現在の真剣交際パートナー」と「ペア専用の暗号鍵材料(pairKey)」を
     自動的に取得し、fetchPairの応答に含めて返す。
   ・pairKeyの生値はユーザーには一切表示せず、ブラウザのメモリ上で
     AES鍵の導出にのみ使う（回答の暗号化・復号のため）。
   ・「入力完了」を押すまでは相手はこちらの回答を見られない。
   ・入力できるのはパートナーのどちらか1人のみ。どちらかが「入力完了」するまでは
     双方入力できる。お相手が入力完了済みの場合（fetchPairの locked === true）は、
     フォームを出さず閲覧専用にする。
   ============================================================ */

const LIFF_ID   = "2010312230-mbcU49bW"; 
const DRAFT_KEY = "proposal_plan_draft_v1";

// ▼▼▼ デプロイ済みGAS Web AppのURL ▼▼▼
const GAS_ENDPOINT = "https://script.google.com/macros/s/AKfycbzZLpG3IWu9IJSQ_7DrX2DAfJbNsaS-yGkXPp7c3ZOdrkKh6I_-4JIwZjaR6C2RaBk9/exec";

/* ============================================================
   Base64URL 変換ユーティリティ（暗号文の符号化に使用）
   ============================================================ */
function bufToBase64Url(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
function base64UrlToBuf(str) {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad    = padded.length % 4;
  const fixed  = pad ? padded + "=".repeat(4 - pad) : padded;
  const binary = atob(fixed);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/* ============================================================
   SHA-256ハッシュ
   ============================================================ */
async function sha256Hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/* ============================================================
   暗号鍵材料からのAES鍵導出
   ・pairKey（生値）はfetchPairの応答で自動的に受け取る。
     ユーザーが目にしたり入力したりすることはない。
   ============================================================ */
async function deriveAesKey(pairKey) {
  const material = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("cipher:" + pairKey));
  return crypto.subtle.importKey("raw", material, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/* ============================================================
   AES-GCM 暗号化ユーティリティ
   ============================================================ */
async function encryptJSON(obj, key) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder().encode(JSON.stringify(obj));
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc);
  const combined = new Uint8Array(iv.length + cipherBuf.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuf), iv.length);
  return bufToBase64Url(combined.buffer);
}
async function decryptJSON(base64, key) {
  const combined = new Uint8Array(base64UrlToBuf(base64));
  const iv   = combined.slice(0, 12);
  const data = combined.slice(12);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

/* ------------------------------------------------------------
   LINEユーザーIDの取得
   ------------------------------------------------------------ */
function getLineUserId() {
  const idToken = liff.getDecodedIDToken();
  if (!idToken || !idToken.sub) {
    throw new Error("ID token is not available (sub claim missing)");
  }
  return idToken.sub;
}

function escapeHTML(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/* ============================================================
   ラジオ・チェックボックスのvalue→表示テキスト変換マップ
   ============================================================ */
const RADIO_LABELS = {
  /* Q1-2 */ "a1_2-1":"事前にお店に一緒に行って婚約指輪を選びたい",
             "a1_2-2":"プロポーズの時はプロポーズリングをもらって、後から一緒に婚約指輪を選びたい",
             "a1_2-3":"婚約指輪の希望はある程度伝えた上で、お店で決めるのは相手に任せる",
             "a1_2-4":"その他",
  /* Q2   */ "a2-1":"レストラン",
             "a2-2":"ホテルの客室",
             "a2-3":"同棲している家もしくはどちらかの自宅",
             "a2-4":"どこでもいい",
             "a2-5":"思い出の場所、その他",
  /* Q3   */ "a3-1":"記念日",
             "a3-2":"誕生日",
             "a3-3":"クリスマス",
             "a3-4":"バレンタイン",
             "a3-5":"その他",
};
const CHECKBOX_LABELS = {
  /* Q1-1 */ "a1_1-1":"指輪",
             "a1_1-2":"花束",
             "a1_1-3":"手紙",
             "a1_1-4":"特にほしいものはない",
             "a1_1-5":"その他",
};
const OTHER_VALUE = { q1_1: "a1_1-5", q1_2: "a1_2-4", q2: "a2-5", q3: "a3-5" };
const RING_VALUE       = "a1_1-1"; // Q1-1「指輪」
const FLOWER_VALUE     = "a1_1-2"; // Q1-1「花束」
const RESTAURANT_VALUE = "a2-1";   // Q2「レストラン」

/* ============================================================
   チェックボックス・ラジオ収集ヘルパー
   ============================================================ */
function getChecked(name) {
  return Array.from(document.querySelectorAll(`input[name="${name}"]:checked`))
    .map(el => el.value || el.closest("label").textContent.trim());
}
function getRadio(name) {
  const el = document.querySelector(`input[name="${name}"]:checked`);
  return el ? (el.value || el.closest("label").textContent.trim()) : "";
}
function toggleDetail(id, show) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.display = show ? "block" : "none";
  if (!show) el.value = "";
}
function updateQ1_2Visibility() {
  const ringChecked = document.querySelector('input[name="q1_1"][value="a1_1-1"]').checked;
  const group = document.getElementById("q1_2_group");
  if (!group) return;
  group.style.display = ringChecked ? "block" : "none";
  if (!ringChecked) {
    document.querySelectorAll('input[name="q1_2"]').forEach(el => (el.checked = false));
    toggleDetail("q1_2_other", false);
  }
}

/* Q1-3（花束の詳細）：Q1-1で「花束」を選択した場合のみ表示 */
function updateQ1_3Visibility() {
  const cb = document.querySelector('input[name="q1_1"][value="a1_1-2"]');
  const group = document.getElementById("q1_3_group");
  if (!cb || !group) return;
  group.style.display = cb.checked ? "block" : "none";
  if (!cb.checked) {
    ["q1_3_size", "q1_3_color"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = "";
    });
  }
}

/* Q2-2（レストランの希望）：Q2で「レストラン」を選択した場合のみ表示 */
function updateQ2_2Visibility() {
  const isRestaurant = getRadio("q2") === RESTAURANT_VALUE;
  const group = document.getElementById("q2_2_group");
  if (group) group.style.display = isRestaurant ? "block" : "none";
  toggleDetail("q2_2", isRestaurant); // 非表示時は入力内容もクリア
}

/* すべての条件付き表示（自由記述欄・Q1-2・Q1-3・Q2-2）を現在の選択状態に合わせる */
function syncConditionalVisibility() {
  toggleDetail("q1_1_other", getChecked("q1_1").includes(OTHER_VALUE.q1_1));
  toggleDetail("q2_other", getRadio("q2") === OTHER_VALUE.q2);
  toggleDetail("q3_other", getRadio("q3") === OTHER_VALUE.q3);
  updateQ1_2Visibility();
  toggleDetail("q1_2_other", getRadio("q1_2") === OTHER_VALUE.q1_2);
  updateQ1_3Visibility();
  updateQ2_2Visibility();
}

/* ============================================================
   フォーム値の収集・復元・検証
   ============================================================ */
function collectFormData() {
  return {
    q1_1:       getChecked("q1_1"),
    q1_1_other: document.getElementById("q1_1_other").value,
    q1_2:       getRadio("q1_2"),
    q1_2_other: document.getElementById("q1_2_other").value,
    q1_3_size:  document.getElementById("q1_3_size").value,
    q1_3_color: document.getElementById("q1_3_color").value,
    q2:         getRadio("q2"),
    q2_other:   document.getElementById("q2_other").value,
    q2_2:       document.getElementById("q2_2").value,
    q3:         getRadio("q3"),
    q3_other:   document.getElementById("q3_other").value,
    q4:         document.getElementById("q4").value,
    q5:         document.getElementById("q5").value,
  };
}

function restoreFormData(data) {
  if (!data) return;
  const setText = (id, val) => {
    const el = document.getElementById(id);
    if (el && val !== undefined) el.value = val;
  };
  const setRadio = (name, val) => {
    if (!val) return;
    let r = document.querySelector(`input[name="${name}"][value="${val}"]`);
    if (!r) {
      document.querySelectorAll(`input[name="${name}"]`).forEach(el => {
        if ((el.closest("label") || {}).textContent &&
            el.closest("label").textContent.trim() === val) r = el;
      });
    }
    if (r) r.checked = true;
  };
  const setCheckboxes = (name, vals) => {
    if (!Array.isArray(vals)) return;
    document.querySelectorAll(`input[name="${name}"]`).forEach(el => {
      const label = el.closest("label");
      const text  = label ? label.textContent.trim() : "";
      if (vals.includes(el.value) || vals.includes(text)) el.checked = true;
    });
  };

  setCheckboxes("q1_1", data.q1_1);
  setText("q1_1_other", data.q1_1_other);
  setRadio("q1_2", data.q1_2);
  setText("q1_2_other", data.q1_2_other);
  setText("q1_3_size", data.q1_3_size);
  setText("q1_3_color", data.q1_3_color);
  setRadio("q2", data.q2);
  setText("q2_other", data.q2_other);
  setText("q2_2", data.q2_2);
  setRadio("q3", data.q3);
  setText("q3_other", data.q3_other);
  setText("q4", data.q4);
  setText("q5", data.q5);

  syncConditionalVisibility();
}

function clearFormFields() {
  ["q1_1_other", "q1_2_other", "q1_3_size", "q1_3_color", "q2_other", "q2_2", "q3_other", "q4", "q5"]
    .forEach(id => { const el = document.getElementById(id); if (el) el.value = ""; });
  document.querySelectorAll('input[type="radio"], input[type="checkbox"]')
    .forEach(el => (el.checked = false));
  syncConditionalVisibility();
}

function validate(data) {
  const errors = [];
  if (!data.q1_1 || data.q1_1.length === 0)
    errors.push("Q1-1: プロポーズの時にほしいものを選択してください。");
  if (data.q1_1 && data.q1_1.includes(OTHER_VALUE.q1_1) && !data.q1_1_other.trim())
    errors.push("Q1-1: 「その他」の内容を入力してください。");
  if (data.q1_1 && data.q1_1.includes(RING_VALUE) && !data.q1_2)
    errors.push("Q1-2: 指輪の準備について選択してください。");
  if (data.q1_2 === OTHER_VALUE.q1_2 && !data.q1_2_other.trim())
    errors.push("Q1-2: 「その他」の内容を入力してください。");
  if (!data.q2)
    errors.push("Q2: プロポーズ場所の希望を選択してください。");
  if (data.q2 === OTHER_VALUE.q2 && !data.q2_other.trim())
    errors.push("Q2: 「思い出の場所、その他」の内容を入力してください。");
  if (data.q3 === OTHER_VALUE.q3 && !data.q3_other.trim())
    errors.push("Q3: 「その他」の内容を入力してください。");
  return errors;
}

function buildAnalyticsPayload(data) {
  const lbl = (val) => (val ? (RADIO_LABELS[val] || val) : "");
  const chkText = (arr) => (Array.isArray(arr) && arr.length > 0)
    ? arr.map(v => CHECKBOX_LABELS[v] || v).join("、")
    : "";
  return {
    q1_1: chkText(data.q1_1),
    q1_1_other: data.q1_1_other || "",
    q1_2: lbl(data.q1_2),
    q1_2_other: data.q1_2_other || "",
    q1_3_size: data.q1_3_size || "",
    q1_3_color: data.q1_3_color || "",
    q2: lbl(data.q2),
    q2_other: data.q2_other || "",
    q2_2: data.q2_2 || "",
    q3: lbl(data.q3),
    q3_other: data.q3_other || "",
    q4: data.q4 || "",
    q5: data.q5 || "",
  };
}

/* ============================================================
   回答の読み取り表示（自分の回答／相手の回答の共通レンダラ）
   ============================================================ */
function renderAnswerRows(data) {
  const r = (val) => (val && String(val).trim()) ? val : "未回答";
  const lblWithOther = (val, other, otherVal) => {
    if (!val) return "未回答";
    const text = RADIO_LABELS[val] || val;
    if (val === otherVal && other && other.trim()) return `${text}：${other.trim()}`;
    return text;
  };
  const chkListHTML = (arr, other) => {
    if (!Array.isArray(arr) || arr.length === 0) return "未回答";
    return arr.map(v => {
      const text = CHECKBOX_LABELS[v] || v;
      if (v === OTHER_VALUE.q1_1 && other && other.trim()) return `・${escapeHTML(text)}：${escapeHTML(other.trim())}`;
      return `・${escapeHTML(text)}`;
    }).join("<br>");
  };

  const rows = [
    { q: "Q1-1 プロポーズの時にほしいものはありますか？", html: chkListHTML(data.q1_1, data.q1_1_other) },
    { q: "Q1-2 プロポーズのときに指輪がほしいと答えた方、事前に一緒に見に行きたいですか？",
      a: (Array.isArray(data.q1_1) && data.q1_1.includes("a1_1-1"))
        ? lblWithOther(data.q1_2, data.q1_2_other, OTHER_VALUE.q1_2)
        : "（指輪を選択していないため対象外）" },
    { q: "Q1-3 プロポーズのときに花束がほしいと答えた方、本数・サイズ、花の種類、色などに要望はありますか？",
      a: (Array.isArray(data.q1_1) && data.q1_1.includes(FLOWER_VALUE))
        ? `本数・サイズ：${r(data.q1_3_size)}\n種類、色：${r(data.q1_3_color)}`
        : "（花束を選択していないため対象外）" },
    { q: "Q2 プロポーズ場所の希望はありますか？", a: lblWithOther(data.q2, data.q2_other, OTHER_VALUE.q2) },
    { q: "Q2-2 レストランでプロポーズしてほしいと答えた方、お店の希望、料理ジャンルの希望などはありますか？",
      a: data.q2 === RESTAURANT_VALUE
        ? r(data.q2_2)
        : "（レストランを選択していないため対象外）" },
    { q: "Q3 プロポーズの日程にこだわりがあれば教えてください。", a: lblWithOther(data.q3, data.q3_other, OTHER_VALUE.q3) },
    { q: "Q4 プロポーズについて、これだけは嫌というものがあれば教えてください。", a: r(data.q4) },
    { q: "Q5 上記の他に理想のプロポーズはありますか？", a: r(data.q5) },
  ];

  return rows.map(({ q, a, html }) => `
    <div class="view-item">
      <p class="view-question">${escapeHTML(q)}</p>
      <p class="view-answer">${html !== undefined ? html : escapeHTML(a).replace(/\n/g, "<br>")}</p>
    </div>
  `).join("");
}

/* ============================================================
   フォーム要素の表示・非表示
   ============================================================ */
function setFormVisible(visible) {
  document.querySelectorAll(
    ".container > label, .container > input, .container > textarea, " +
    ".container > #q1_2_group, .container > #q1_3_group, .container > #q2_2_group, " +
    ".container > div.button-group"
  ).forEach(el => (el.style.display = visible ? "" : "none"));
  // 表示に戻すときは、条件付きの欄（Q1-2/1-3/2-2・その他欄）を選択状態に合わせ直す
  if (visible) syncConditionalVisibility();
}

function getOrCreateContainer(id) {
  let el = document.getElementById(id);
  if (!el) {
    el = document.createElement("div");
    el.id = id;
    document.querySelector(".container").prepend(el);
  }
  return el;
}

/* ============================================================
   状態表示（鍵検証中・エラーなど）
   ============================================================ */
function showStateCard(title, text, isLoading = false) {
  setFormVisible(false);
  const container = getOrCreateContainer("viewMode");
  container.style.display = "block";
  container.innerHTML = `
    <div class="view-header state-card">
      ${isLoading ? `
        <div class="state-spinner">
          <img src="https://developers.line.biz/media/line-mini-app/LINE_spinner_light.svg" class="spinner-light" alt="読み込み中">
          <img src="https://developers.line.biz/media/line-mini-app/LINE_spinner_dark.svg" class="spinner-dark" alt="読み込み中">
        </div>
      ` : ""}
      <p class="view-label">${escapeHTML(title)}</p>
      <p class="state-text">${escapeHTML(text)}</p>
    </div>
  `;
}
function hideStateCard() {
  const el = document.getElementById("viewMode");
  if (el) { el.style.display = "none"; el.innerHTML = ""; }
  const partnerRequired = document.getElementById("partnerRequired");
  if (partnerRequired) partnerRequired.style.display = "none";
}

/* ============================================================
   パートナー未登録／交際終了時の案内
   （既存の「パートナー登録が必要です」CTAカードを、状況に応じた
   文言に差し替えて使う）
   ============================================================ */
function partnerReasonToText(reason) {
  switch (reason) {
    case "partner_ended":
      return {
        title: "パートナー登録が必要です",
        text: "プロポーズプランは、真剣交際のパートナー登録が完了した方のみご利用いただけます。先にパートナー登録を済ませてください。"
      };
    case "no_partner":
      return {
        title: "パートナー登録が必要です",
        text: "プロポーズプランは、真剣交際のパートナー登録が完了した方のみご利用いただけます。先にパートナー登録を済ませてください。"
      };
    default:
      return {
        title: "読み込みに失敗しました",
        text: "時間をおいてもう一度開き直してください。"
      };
  }
}

function showPartnerRequired(reason) {
  setFormVisible(false);
  hideStateCard();
  const { title, text } = partnerReasonToText(reason);
  const partnerRequired = document.getElementById("partnerRequired");
  if (partnerRequired) {
    const titleEl = partnerRequired.querySelector(".cta-title");
    const textEl = partnerRequired.querySelector(".cta-text");
    if (titleEl) titleEl.textContent = title;
    if (textEl) textEl.innerHTML = escapeHTML(text).replace(/\n/g, "<br>");
    partnerRequired.style.display = "block";
  } else {
    showStateCard(title, text);
  }
}


/* ============================================================
   下書きの保存：二段構え
   ① 自動保存 … 入力のたびに端末（localStorage）へ保存
   ② 「下書き保存」ボタン（プレビュー画面上部）… 端末 ＋ クラウド（GAS）へ保存
   端末のデータが消えても、クラウド側から自動復元する。
   クラウド側は「LINEユーザーID由来の鍵」で暗号化してから送るため、
   サーバー側では内容を読めない。
   ※ここで保存する下書きは「自分だけの下書き」であり、お相手には届かない
     （お相手に届くのは「入力完了」にした内容だけ）。
   ============================================================ */
// 「フォームクリア」した時刻。これ以前のクラウド下書きは自動復元しない（意図的な削除を尊重するため）
const DRAFT_CLEARED_AT_KEY = "proposal_plan_draft_cleared_at";
// この端末が最後に把握した（保存した／読み込んだ／確認して見送った）クラウド下書きの版（保存時刻）
const DRAFT_SYNCED_AT_KEY = "proposal_plan_draft_cloud_synced_at";
// クラウド下書きの暗号鍵導出用（LINEユーザーIDと組み合わせる）。変更すると過去のクラウド下書きは復号できなくなる
const DRAFT_CRYPTO_SALT = "proposal_plan_draft_key_v1:";

/* ----- 端末（localStorage） ----- */
function readLocalDraft() {
  try {
    const raw = localStorage.getItem(DRAFT_KEY); if (!raw) return null;
    const parsed = JSON.parse(raw);
    const { savedAt, ...data } = parsed;
    return { data, savedAt: Number(savedAt) || 0 }; // 旧形式は savedAt なし → 0
  } catch (e) { console.warn("local draft read failed", e); return null; }
}
function writeLocalDraft(data, savedAt = Date.now()) {
  try { localStorage.setItem(DRAFT_KEY, JSON.stringify({ ...data, savedAt })); return true; }
  catch (e) { console.warn("local draft write failed", e); return false; }
}
function getDraftClearedAt() {
  try { return Number(localStorage.getItem(DRAFT_CLEARED_AT_KEY)) || 0; } catch (_) { return 0; }
}
function setDraftClearedAt(ts) {
  try { localStorage.setItem(DRAFT_CLEARED_AT_KEY, String(ts)); } catch (_) {}
}
/* この端末が最後に把握したクラウド下書きの「版」。
   端末ごとの時計のずれに左右されないよう、時刻の大小ではなく
   「別の版かどうか（＝別の端末などで更新されたか）」の判定に使う。 */
function getCloudSyncedAt() {
  try { return Number(localStorage.getItem(DRAFT_SYNCED_AT_KEY)) || 0; } catch (_) { return 0; }
}
function setCloudSyncedAt(ts) {
  try { localStorage.setItem(DRAFT_SYNCED_AT_KEY, String(ts)); } catch (_) {}
}

/* ----- クラウド（GAS） ----- */
function fetchWithTimeout(url, options = {}, ms = 15000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { ...options, signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

// 鍵は「ソルト＋LINEユーザーID」のSHA-256。サーバーが持つのはユーザーIDのハッシュ（ownerHash）だけで、
// この鍵は導出できない。パートナー登録の状態（pairKey）には依存しない。
async function getDraftCryptoKey(userId) {
  const raw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(DRAFT_CRYPTO_SALT + userId));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function saveCloudDraft(data, savedAt = Date.now()) {
  const userId     = getLineUserId();
  const ownerHash  = await sha256Hex(userId);
  const key        = await getDraftCryptoKey(userId);
  const cipherText = await encryptJSON(data, key);

  const resp = await fetchWithTimeout(GAS_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" }, // preflight回避
    body: JSON.stringify({ action: "saveDraft", ownerHash, cipherText, savedAt, schemaVersion: 1 }),
  });
  const result = await resp.json();
  if (!result.ok) throw new Error(result.reason || "save_draft_failed");
  setCloudSyncedAt(savedAt); // この端末が保存した版 ＝ 把握済み
  return savedAt;
}

async function loadCloudDraft() {
  const userId    = getLineUserId();
  const ownerHash = await sha256Hex(userId);
  const key       = await getDraftCryptoKey(userId);

  const url  = `${GAS_ENDPOINT}?action=loadDraft&ownerHash=${encodeURIComponent(ownerHash)}`;
  const resp = await fetchWithTimeout(url, { method: "GET" });
  const result = await resp.json();
  if (!result.ok) {
    if (result.reason === "not_found") return null;
    throw new Error(result.reason || "load_draft_failed");
  }
  const data = await decryptJSON(result.cipherText, key);
  return { data, savedAt: Number(result.savedAt) || 0 };
}

/* ----- 起動時：クラウドの下書きを確認して必要なら復元（画面表示はブロックしない） ----- */
async function syncCloudDraft(onRestored) {
  let cloud;
  try {
    cloud = await loadCloudDraft();
  } catch (e) { console.warn("cloud draft load skipped:", e); return; }
  if (!cloud || isBlankDraftData(cloud.data)) return;
  if (cloud.savedAt <= getDraftClearedAt()) return; // クリア済み

  const current = currentDraftData();
  const restore = () => {
    applyDraftData(cloud.data);
    writeLocalDraft(cloud.data, cloud.savedAt);
    if (typeof onRestored === "function") onRestored();
  };

  // 端末側が空（端末のデータが消えた／新しい端末）→ 自動で復元
  if (isBlankDraftData(current)) { restore(); setCloudSyncedAt(cloud.savedAt); return; }

  // 端末側にも入力あり。
  // この端末が最後に把握した版と違う（＝別の端末などで更新された）かつ、内容も違う場合だけ確認する
  if (cloud.savedAt === getCloudSyncedAt()) return; // 把握済みの版
  const norm = d => JSON.stringify(d);
  if (norm(cloud.data) === norm(current)) { setCloudSyncedAt(cloud.savedAt); return; }
  const when = cloud.savedAt ? new Date(cloud.savedAt).toLocaleString("ja-JP") : "";
  if (confirm("クラウドに、別の端末などで保存された下書きがあります" + (when ? "（" + when + "）" : "") +
              "。読み込みますか？\n（読み込むと、いま画面にある入力内容は置き換わります）")) {
    restore();
  }
  setCloudSyncedAt(cloud.savedAt); // 読み込んだ場合も、見送った場合も「確認済み」にする
}


/* 現在の画面の入力内容（下書き対象） */
function currentDraftData() { return collectFormData(); }

/* 入力が空（初期状態）かどうか */
function isBlankDraftData(d) {
  if (!d) return true;
  return !Object.values(d).some(v => Array.isArray(v) ? v.length > 0 : String(v || "").trim() !== "");
}

/* 下書きデータを画面に反映する（端末・クラウド共通。いまの入力は置き換える） */
function applyDraftData(data) {
  clearFormFields();
  restoreFormData(data);
}

/* クラウド下書きの確認は、ページを開いて最初に入力フォームを出した時の1回だけ行う */
let cloudDraftChecked = false;
function syncCloudDraftOnce() {
  if (cloudDraftChecked) return;
  cloudDraftChecked = true;
  syncCloudDraft();
}

/* ============================================================
   回答画面の状態管理（自動ペア判定）
   ============================================================ */
const AppState = { pairKey: null, ownerHash: null };

async function fetchPair(ownerHash) {
  const url = `${GAS_ENDPOINT}?action=fetchPair&ownerHash=${encodeURIComponent(ownerHash)}`;
  const resp = await fetch(url, { method: "GET" });
  return resp.json();
}

/* GASの起動待ち（コールドスタート）を、本番の通信より前に済ませておくための軽い呼び出し。
   結果は使わず、失敗しても何もしない。 */
function warmUpGas() {
  try {
    fetch(`${GAS_ENDPOINT}?action=ping`, { method: "GET" }).catch(() => {});
  } catch (_) {}
}

/* prefetched: 先に開始しておいた fetchPair の Promise（無ければここで取得する） */
async function initAnswerScreen(ownerHash, prefetched) {
  AppState.ownerHash = ownerHash;
  showStateCard("読み込み中", "パートナー情報を確認しています…", true);

  let result;
  try {
    result = await (prefetched || fetchPair(ownerHash));
  } catch (e) {
    console.error("fetchPair failed", e);
    showPartnerRequired("server_error");
    return;
  }

  if (!result.ok) {
    showPartnerRequired(result.reason);
    return;
  }

  AppState.pairKey = result.pairKey;
  hideStateCard();
  await renderAnswerScreen(result);
}

async function refetchPair() {
  let result;
  try {
    result = await fetchPair(AppState.ownerHash);
  } catch (e) {
    console.error("fetchPair failed", e);
    showPartnerRequired("server_error");
    return null;
  }
  if (!result.ok) {
    // 取得中に交際終了などがあった場合は案内画面に戻す
    showPartnerRequired(result.reason);
    return null;
  }
  AppState.pairKey = result.pairKey;
  return result;
}

/* fetchResult: { own: {cipherText, completed, updatedAt} | null, partner: {completed, cipherText?, updatedAt?} } */
async function renderAnswerScreen(fetchResult) {
  const aesKey = await deriveAesKey(AppState.pairKey);

  // お相手が既に入力している場合は、入力フォームを出さず閲覧専用の画面にする
  if (fetchResult.locked) {
    await renderLockedView(fetchResult.partner, aesKey);
    return;
  }

  const ownCompleted = !!(fetchResult.own && fetchResult.own.completed);

  if (ownCompleted) {
    let ownData = null;
    try { ownData = await decryptJSON(fetchResult.own.cipherText, aesKey); }
    catch (e) {
      console.error("decrypt own answer failed", e);
      showStateCard("復号に失敗しました", "時間をおいてもう一度開き直してください。改善しない場合はご連絡ください。");
      return;
    }
    renderCompletedView(ownData, fetchResult.partner, aesKey);
  } else {
    // まだ入力完了していない → 編集可能なフォームを表示（下書きがあれば復元）
    setFormVisible(true);
    hideStateCard();
    try {
      const local = readLocalDraft();
      if (local) restoreFormData(local.data);
    } catch (_) {}
    wireSubmitButton(aesKey);
    syncCloudDraftOnce(); // クラウドの下書きを確認（裏で実行。画面表示は止めない）
  }
}

/* ============================================================
   お相手が既に入力している場合の閲覧専用ビュー（入力フォームは出さない）
   ============================================================ */
async function renderLockedView(partner, aesKey) {
  setFormVisible(false);
  const statusEl = document.getElementById("statusBanner");
  if (statusEl) statusEl.remove();

  const container = getOrCreateContainer("viewMode");
  container.style.display = "block";

  const partnerDone = !!(partner && partner.completed);
  let bodyHTML;
  if (partnerDone) {
    try {
      const partnerData = await decryptJSON(partner.cipherText, aesKey);
      bodyHTML = `
        <div class="view-header"><p class="view-label">お相手の回答</p></div>
        ${renderAnswerRows(partnerData)}
      `;
    } catch (e) {
      console.error("decrypt partner answer failed", e);
      bodyHTML = `<div class="view-header state-card"><p class="state-text">お相手の回答の復号に失敗しました。</p></div>`;
    }
  } else {
    bodyHTML = `
      <div class="cta-card" style="border-style:dashed;">
        <div class="cta-content" style="text-align:center;">
          <p class="cta-text" style="margin:0;">お相手が入力中です。入力が完了すると、ここに回答が表示されます。</p>
        </div>
      </div>
    `;
  }

  container.innerHTML = `
    <div class="view-header state-card">
      <p class="view-label">${partnerDone ? "お相手がすでに入力しています" : "お相手が入力を開始しています"}</p>
      <p class="state-text">このプランはパートナーのどちらか1人のみが入力します。そのため、あなたは入力できません。</p>
    </div>
    ${bodyHTML}
    <div style="margin:20px 0;">
      <button type="button" id="refreshPairBtn" style="width:100%; padding:12px; border-radius:12px; background:#fafafa; color:#888; border:1px solid #ddd; font-size:14px; cursor:pointer;">
        お相手の状況を更新する
      </button>
    </div>
  `;

  document.getElementById("refreshPairBtn").addEventListener("click", async () => {
    const result = await refetchPair();
    if (result) await renderAnswerScreen(result);
  });
}

function wireSubmitButton(aesKey) {
  const submitBtn = document.getElementById("submitBtn");
  if (!submitBtn) return;
  submitBtn.textContent = "入力完了にする";
  submitBtn.onclick = async () => {
    const data = collectFormData();
    const errors = validate(data);
    if (errors.length > 0) {
      alert("以下の項目を入力・選択してください。\n\n" + errors.join("\n"));
      return;
    }
    if (!confirm("「入力完了」にすると、お相手はこのプランに入力できなくなります。よろしいですか？")) return;
    writeLocalDraft(data);

    submitBtn.disabled = true;
    const originalLabel = submitBtn.textContent;
    submitBtn.textContent = "送信中…";
    try {
      const submitResult = await submitAnswer(data, true, aesKey);
      // サーバーが保存後の最新状況(pair)を一緒に返すので、取り直しの通信は不要。
      // （古いサーバー応答で pair が無い場合のみ、従来どおり取り直す）
      let result = submitResult && submitResult.pair && submitResult.pair.ok ? submitResult.pair : null;
      if (result) AppState.pairKey = result.pairKey;
      else result = await refetchPair();
      if (result) await renderAnswerScreen(result);
    } catch (e) {
      console.error("submit error", e);
      if (e && e.message === "partner_already_answered") {
        // 開いている間にお相手が先に入力した場合：入力不可の画面に切り替える
        alert("お相手がすでに入力を完了しているため、入力できません。お相手の回答を表示します。");
        const latest = await refetchPair();
        if (latest) await renderAnswerScreen(latest);
      } else {
        alert("送信に失敗しました。通信環境を確認してもう一度お試しください。");
      }
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = originalLabel;
    }
  };
}

async function submitAnswer(data, completed, aesKey) {
  const cipherText = await encryptJSON(data, aesKey);
  const analytics  = buildAnalyticsPayload(data);
  const resp = await fetch(GAS_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify({
      action: "submit",
      ownerHash: AppState.ownerHash,
      cipherText, completed, analytics
    }),
  });
  const result = await resp.json();
  if (!result.ok) throw new Error(result.reason || "submit_failed");
  return result;
}

/* ============================================================
   入力完了後のビュー：自分の回答（読み取り専用）＋相手の回答
   ============================================================ */
function renderCompletedView(ownData, partner, aesKey) {
  setFormVisible(false);
  const statusEl = document.getElementById("statusBanner");
  if (statusEl) statusEl.remove();

  const container = getOrCreateContainer("viewMode");
  container.style.display = "block";

  (async () => {
    // 入力できるのは1人のみ。お相手の入力待ちカードは出さない
    // （以前の仕様で両者が入力済みのデータがある場合のみ、お相手の回答を表示する）
    let partnerHTML = "";
    if (partner && partner.completed) {
      try {
        const partnerData = await decryptJSON(partner.cipherText, aesKey);
        partnerHTML = `
          <div class="view-header"><p class="view-label">お相手の回答</p></div>
          ${renderAnswerRows(partnerData)}
        `;
      } catch (e) {
        console.error("decrypt partner answer failed", e);
        partnerHTML = `<div class="view-header state-card"><p class="state-text">お相手の回答の復号に失敗しました。</p></div>`;
      }
    }

    container.innerHTML = `
      <div class="view-header">
        <p class="view-label">あなたの回答（入力完了）</p>
      </div>
      ${renderAnswerRows(ownData)}
      <div style="margin:20px 0;">
        <button type="button" id="editAnswerBtn" style="width:100%; padding:14px; border-radius:12px; background:#fff; color:#d96c7d; border:2px solid #f0c5cc; font-size:15px; font-weight:600; cursor:pointer;">
          回答を編集する
        </button>
      </div>
      ${partnerHTML ? `<div style="margin:28px 0 12px; border-top:1px dashed #f0c5cc;"></div>${partnerHTML}` : ""}
    `;

    document.getElementById("editAnswerBtn").addEventListener("click", async () => {
      if (!confirm("回答を編集すると「未入力」の状態に戻り、編集が終わって再度「入力完了」を押すまでお相手には見えなくなります。編集しますか？")) return;
      try {
        await submitAnswer(ownData, false, aesKey);
      } catch (e) {
        console.error("revert to incomplete failed", e);
        if (e && e.message === "partner_already_answered") {
          alert("お相手がすでに入力を完了しているため、編集できません。");
          const latest = await refetchPair();
          if (latest) await renderAnswerScreen(latest);
          return;
        }
        alert("処理に失敗しました。通信環境を確認してもう一度お試しください。");
        return;
      }
      hideStateCard();
      setFormVisible(true);
      restoreFormData(ownData);
      writeLocalDraft(ownData);
      wireSubmitButton(aesKey);
    });
  })();
}

/* ============================================================
   友だち追加チェック
   ============================================================ */
async function checkFriendship() {
  try {
    const friendship = await liff.getFriendship();
    if (!friendship.friendFlag) {
      try { await liff.requestFriendship(); }
      catch (error) { console.warn("友だち追加リクエスト失敗:", error); }
    }
  } catch (error) {
    console.warn("友だち確認をスキップ:", error);
  }
}

/* ============================================================
   メイン処理
   ============================================================ */
(async () => {
  warmUpGas(); // LIFFの初期化と並行して、GASを先に起こしておく
  try {
    await liff.init({ liffId: LIFF_ID });
  } catch (e) {
    console.error("LIFF init failed", e);
    alert("LIFFの初期化に失敗しました。");
    return;
  }

  if (!liff.isLoggedIn()) {
    liff.login();
    return;
  }

  // パートナー確認は、友だち確認(最大でダイアログ待ち)を待たずに先に始める
  const ownerHash = await sha256Hex(getLineUserId());
  const pairPromise = fetchPair(ownerHash);
  pairPromise.catch(() => {}); // 結果は後で await するので、ここでは未処理エラー扱いにしない

  await checkFriendship();

  /* ----- 条件付き表示：自由記述欄の表示制御 ----- */
  document.querySelectorAll('input[name="q1_1"]').forEach(cb =>
    cb.addEventListener("change", () => {
      toggleDetail("q1_1_other", getChecked("q1_1").includes(OTHER_VALUE.q1_1));
      updateQ1_2Visibility();
      updateQ1_3Visibility();
    })
  );
  document.querySelectorAll('input[name="q2"]').forEach(r =>
    r.addEventListener("change", updateQ2_2Visibility)
  );
  [
    { name: "q1_2", otherId: "q1_2_other", otherVal: OTHER_VALUE.q1_2 },
    { name: "q2",   otherId: "q2_other",   otherVal: OTHER_VALUE.q2 },
    { name: "q3",   otherId: "q3_other",   otherVal: OTHER_VALUE.q3 },
  ].forEach(({ name, otherId, otherVal }) => {
    document.querySelectorAll(`input[name="${name}"]`).forEach(r =>
      r.addEventListener("change", () => toggleDetail(otherId, r.value === otherVal))
    );
  });
  syncConditionalVisibility();

  /* ----- 下書き保存 ----- */
  document.getElementById("draftBtn") &&
  document.getElementById("draftBtn").addEventListener("click", async () => {
    const draftBtn = document.getElementById("draftBtn");
    const data = collectFormData();
    if (isBlankDraftData(data)) { alert("入力内容がまだありません。"); return; }

    // 端末とクラウドの両方に保存（同じ時刻を版として記録）
    const savedAt = Date.now();
    const localOk = writeLocalDraft(data, savedAt);

    const originalLabel = draftBtn.textContent;
    draftBtn.disabled = true; draftBtn.textContent = "保存中…";
    try {
      await saveCloudDraft(data, savedAt);
      alert(localOk
        ? "下書きを保存しました。\n（この端末とクラウドの両方に保存されています）\n※お相手には届いていません。"
        : "クラウドに下書きを保存しました。\n（この端末への保存は失敗しました）\n※お相手には届いていません。");
    } catch (e) {
      console.warn("cloud draft save failed:", e);
      alert(localOk
        ? "この端末には保存しましたが、クラウドへの保存に失敗しました。\n通信環境を確認して、もう一度お試しください。"
        : "下書きの保存に失敗しました。通信環境を確認して、もう一度お試しください。");
    } finally {
      draftBtn.disabled = false; draftBtn.textContent = originalLabel;
    }
  });

  /* ----- フォームクリア ----- */
  document.getElementById("clearBtn") &&
  document.getElementById("clearBtn").addEventListener("click", () => {
    if (!confirm("入力内容をすべてクリアしますか？")) return;
    clearFormFields();
    try { localStorage.removeItem(DRAFT_KEY); } catch (_) {}
    setDraftClearedAt(Date.now()); // 意図的な削除。これ以前のクラウド下書きは自動復元しない
  });

  /* ----- パートナー判定→回答画面へ（ユーザー操作は不要） ----- */
  await initAnswerScreen(ownerHash, pairPromise);
})();
