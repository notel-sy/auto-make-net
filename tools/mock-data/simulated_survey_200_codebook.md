# Simulated Survey Codebook

- Data type: synthetic practice dataset
- Warning: not real respondents; for analysis practice only
- Rows: 200

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
