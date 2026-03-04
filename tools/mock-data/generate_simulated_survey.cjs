const fs = require("fs");
const path = require("path");

const outDir = path.join("tools", "mock-data");
fs.mkdirSync(outDir, { recursive: true });

const N = 200;

function rand(min, max) {
  return Math.random() * (max - min) + min;
}

function randInt(min, max) {
  return Math.floor(rand(min, max + 1));
}

function clamp(v, min, max) {
  return Math.max(min, Math.min(max, v));
}

function pickWeighted(items) {
  const total = items.reduce((s, x) => s + x.w, 0);
  let r = Math.random() * total;
  for (const item of items) {
    r -= item.w;
    if (r <= 0) return item.v;
  }
  return items[items.length - 1].v;
}

function randn() {
  const u = 1 - Math.random();
  const v = 1 - Math.random();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

const genderDist = [
  { v: "male", w: 0.46 },
  { v: "female", w: 0.52 },
  { v: "other", w: 0.02 }
];

const ageDist = [
  { v: "18-22", w: 0.18 },
  { v: "23-29", w: 0.34 },
  { v: "30-39", w: 0.30 },
  { v: "40-49", w: 0.13 },
  { v: "50+", w: 0.05 }
];

const tierDist = [
  { v: "tier1", w: 0.24 },
  { v: "tier2", w: 0.35 },
  { v: "tier3", w: 0.26 },
  { v: "tier4plus", w: 0.15 }
];

const eduDist = [
  { v: "highschool_or_below", w: 0.12 },
  { v: "college", w: 0.31 },
  { v: "bachelor", w: 0.43 },
  { v: "master_plus", w: 0.14 }
];

const incomeDist = [
  { v: "<5k", w: 0.24 },
  { v: "5k-10k", w: 0.34 },
  { v: "10k-20k", w: 0.28 },
  { v: ">20k", w: 0.14 }
];

const freqDist = [
  { v: "daily", w: 0.30 },
  { v: "weekly", w: 0.38 },
  { v: "monthly", w: 0.22 },
  { v: "rarely", w: 0.10 }
];

const deviceDist = [
  { v: "mobile", w: 0.74 },
  { v: "desktop", w: 0.22 },
  { v: "tablet", w: 0.04 }
];

const openTextTags = [
  { v: "price", w: 0.21 },
  { v: "performance", w: 0.24 },
  { v: "ui", w: 0.19 },
  { v: "stability", w: 0.16 },
  { v: "feature_request", w: 0.20 }
];

function baseFromFreq(freq) {
  if (freq === "daily") return 4.1;
  if (freq === "weekly") return 3.7;
  if (freq === "monthly") return 3.3;
  return 2.9;
}

const rows = [];
let validCount = 0;

for (let i = 1; i <= N; i += 1) {
  const gender = pickWeighted(genderDist);
  const age_group = pickWeighted(ageDist);
  const city_tier = pickWeighted(tierDist);
  const education = pickWeighted(eduDist);
  const monthly_income = pickWeighted(incomeDist);
  const usage_freq = pickWeighted(freqDist);
  const device = pickWeighted(deviceDist);

  const latent = clamp(baseFromFreq(usage_freq) + randn() * 0.7, 1, 5);

  let q1_easy_use = clamp(Math.round(latent + randn() * 0.7), 1, 5);
  let q2_visual_design = clamp(Math.round(latent + randn() * 0.8), 1, 5);
  let q3_response_speed = clamp(Math.round(latent + randn() * 0.6), 1, 5);
  let q4_feature_fit = clamp(Math.round(latent + randn() * 0.7), 1, 5);
  let q5_value_money = clamp(Math.round((latent - 0.2) + randn() * 0.9), 1, 5);
  let q6_intent_continue = clamp(Math.round((latent + 0.1) + randn() * 0.7), 1, 5);

  const meanLikert = (q1_easy_use + q2_visual_design + q3_response_speed + q4_feature_fit + q5_value_money + q6_intent_continue) / 6;
  const satisfaction = clamp(Math.round(meanLikert + randn() * 0.4), 1, 5);
  const recommend_nps = clamp(Math.round((satisfaction - 1) * 2.5 + randn() * 1.8 + 2), 0, 10);

  const attention_check = Math.random() < 0.92 ? 1 : 0;

  let completion_seconds = Math.round(clamp(220 + randn() * 80, 35, 700));
  if (Math.random() < 0.05) {
    completion_seconds = randInt(35, 85);
  }

  let straightline_flag = 0;
  if (Math.random() < 0.04) {
    const lineValue = randInt(1, 5);
    q1_easy_use = lineValue;
    q2_visual_design = lineValue;
    q3_response_speed = lineValue;
    q4_feature_fit = lineValue;
    q5_value_money = lineValue;
    q6_intent_continue = lineValue;
    straightline_flag = 1;
  }

  const is_valid = attention_check === 1 && completion_seconds >= 90 && straightline_flag === 0 ? 1 : 0;
  if (is_valid === 1) validCount += 1;

  rows.push({
    id: i,
    gender,
    age_group,
    city_tier,
    education,
    monthly_income,
    usage_freq,
    q1_easy_use,
    q2_visual_design,
    q3_response_speed,
    q4_feature_fit,
    q5_value_money,
    q6_intent_continue,
    satisfaction,
    recommend_nps,
    attention_check,
    completion_seconds,
    straightline_flag,
    device,
    open_text_tag: pickWeighted(openTextTags),
    is_valid
  });
}

const headers = Object.keys(rows[0]);
const csvLines = [headers.join(",")];
for (const row of rows) {
  csvLines.push(headers.map((h) => String(row[h])).join(","));
}

const csvPath = path.join(outDir, "simulated_survey_200.csv");
fs.writeFileSync(csvPath, csvLines.join("\n") + "\n", "utf8");

const summary = {
  note: "SIMULATED DATA ONLY - DO NOT USE AS REAL SURVEY RESULTS",
  generated_at: new Date().toISOString(),
  total_rows: N,
  valid_rows: validCount,
  invalid_rows: N - validCount,
  valid_rate: Number((validCount / N).toFixed(4))
};

const summaryPath = path.join(outDir, "simulated_survey_200_summary.json");
fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2) + "\n", "utf8");

const codebook = `# Simulated Survey Codebook

- Data type: synthetic practice dataset
- Warning: not real respondents; for analysis practice only
- Rows: ${N}

## Fields

- id: respondent id (1..200)
- gender: male/female/other
- age_group: 18-22/23-29/30-39/40-49/50+
- city_tier: tier1/tier2/tier3/tier4plus
- education: highschool_or_below/college/bachelor/master_plus
- monthly_income: <5k/5k-10k/10k-20k/>20k
- usage_freq: daily/weekly/monthly/rarely
- q1_easy_use: Likert 1-5
- q2_visual_design: Likert 1-5
- q3_response_speed: Likert 1-5
- q4_feature_fit: Likert 1-5
- q5_value_money: Likert 1-5
- q6_intent_continue: Likert 1-5
- satisfaction: overall satisfaction (1-5)
- recommend_nps: NPS style score (0-10)
- attention_check: 1 pass, 0 fail
- completion_seconds: answer duration in seconds
- straightline_flag: 1 means potential straight-line responses
- device: mobile/desktop/tablet
- open_text_tag: coded open text category
- is_valid: 1 valid / 0 invalid (rule: attention_check=1 and completion_seconds>=90 and straightline_flag=0)

## Suggested practice workflow

1. Filter is_valid=1 for core analysis.
2. Run descriptive stats and cross-tabs.
3. Compute reliability for q1-q6.
4. Model recommend_nps or satisfaction.
`;

const codebookPath = path.join(outDir, "simulated_survey_200_codebook.md");
fs.writeFileSync(codebookPath, codebook, "utf8");

console.log(JSON.stringify({ csvPath, summaryPath, codebookPath, validCount }, null, 2));
