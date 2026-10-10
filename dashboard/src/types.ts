export interface TargetConfig {
  id: string;
  name: string;
  valid: boolean;
  validation_error: string | null;
}

export interface TraceStep {
  step_type: string;
  content?: string;
  tool_name?: string;
  tool_args?: Record<string, any>;
  timestamp?: string;
  metadata?: Record<string, any>;
}

export interface Trace {
  target_id: string;
  kind: string;
  variant_source: string;
  parent_run_id: string | null;
  round: number;
  steps: TraceStep[];
}

export interface Run {
  run_id: string;
  assessment_id: string;
  target_id: string;
  name: string;
  kind: string;
  variant_source: 'seed' | 'generated' | 'recorded';
  parent_run_id: string | null;
  round: number;
  verdict: 'confirmed_exploit' | 'blocked' | 'legitimate_pass' | 'inconclusive' | 'error';
  timestamp: string;
  trace: Trace;
  feedback?: {
    type: 'bot_reply' | 'deny_reason';
    rule?: string;
    text: string;
  };
}

export interface Finding {
  finding_id: string;
  target_id: string;
  source: 'seed' | 'generated' | 'recorded';
  rule_fired: 'canary_in_executed_args' | 'canary_in_final_reply' | 'executed_outside_policy' | 'memory_write_untrusted';
  description: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  trace_id?: string;
  details?: Record<string, any>;
}

export interface Defense {
  id: string;
  name: string;
  target_component: string;
  status: 'enforced' | 'disabled' | 'stub';
  is_stub: boolean;
  description: string;
  mitigation_rule: string;
  denial_message?: string;
}

export interface RetestResults {
  status: string;
  timestamp: string;
  before: {
    attacks_tested: number;
    confirmed_exploits: number;
    exploit_rate: number | null;
    exploit_rate_display: string;
    legitimate_tasks_tested: number;
    legitimate_tasks_passed: number;
    legitimate_pass_rate: number | null;
    legitimate_pass_rate_display: string;
  } | null;
  after: {
    attacks_tested: number;
    confirmed_exploits: number;
    exploit_rate: number | null;
    exploit_rate_display: string;
    legitimate_tasks_tested: number;
    legitimate_tasks_passed: number;
    legitimate_pass_rate: number | null;
    legitimate_pass_rate_display: string;
  } | null;
  defense_evaluation_note?: string;
}

export interface AssessmentReport {
  assessment_id: string;
  assessment_name: string;
  target_id: string;
  target_name: string;
  generated_at: string;
  summary: {
    total_runs: number;
    attack_runs: number;
    confirmed_exploits: number;
    blocked_attempts: number;
    inconclusive_runs: number;
    error_runs: number;
    exploit_breakdown_statement: string;
  };
  findings_metrics: {
    total_findings: number;
    seed_findings_count: number;
    adaptive_generated_findings_count: number;
    recorded_findings_count: number;
    unresolved_findings_count: number;
  };
  findings_list: Finding[];
  defenses_status: Defense[];
  retest_comparison: RetestResults | null;
  evidence_integrity: {
    chain_length: number;
    last_block_hash: string | null;
  };
  mandatory_disclosures: {
    discovery_methodology: string;
    leak_detection_capability: string;
    defense_limitations: string;
    canary_matching_limitation: string;
    target_compatibility_scope: string;
  };
}

export interface ChainVerification {
  verified: boolean;
  chain_length: number;
  last_block_hash?: string;
  tampered_index?: number;
  message: string;
}

export interface AssessmentSummary {
  id: string;
  name: string;
  target_id?: string;
  target_name?: string;
  status: string;
  created_at: string;
  updated_at: string;
  runs_count: number;
  findings_count: number;
}
