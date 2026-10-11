/**
 * AgentBreak Sentinel - TypeScript Schemas and Message Types
 */

export type RiskLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'CLEAN';

export interface ScannerRuleMatch {
  rule_id: string;
  rule_name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  confidence: string;
  matched_snippet: string;
  explanation: string;
  mitigation: string;
}

export interface LocalScanReport {
  status: 'completed';
  risk_level: RiskLevel;
  rules_matched: ScannerRuleMatch[];
  summary: string;
  is_heuristic_only: true;
  is_trace_verified: false;
  content_length: number;
  timestamp: string;
}

export interface BackendScanResponse {
  scan_id: string;
  timestamp: string;
  status: string;
  risk_level: RiskLevel;
  content_length: number;
  sanitized_excerpt: string;
  rules_matched: ScannerRuleMatch[];
  summary: string;
  is_heuristic_only: boolean;
  is_trace_verified: boolean;
  linked_assessment_id?: string | null;
  mitigation_advice: string[];
  privacy_notice: string;
}

export interface ExtensionSettings {
  apiBaseUrl: string;
  targetId: string;
  activeAssessmentId?: string;
  offlineMode: boolean;
}

export interface SupportedContextInfo {
  isSupported: boolean;
  contextName: string;
  url: string;
  canInspectMessages: boolean;
}

export interface ExtractedMessage {
  id: string;
  sender: 'user' | 'assistant' | 'system';
  text: string;
  snippet: string;
}

// Typed Messages between Extension Components
export type ExtensionMessage =
  | { type: 'CHECK_SUPPORTED_STATUS' }
  | { type: 'GET_SELECTED_TEXT' }
  | { type: 'GET_PAGE_MESSAGES' }
  | { type: 'RUN_LOCAL_SCAN'; payload: { text: string } }
  | { type: 'SUBMIT_BACKEND_SCAN'; payload: { text: string; consentGiven: boolean; contextUrl?: string } }
  | { type: 'GET_SETTINGS' }
  | { type: 'SAVE_SETTINGS'; payload: Partial<ExtensionSettings> }
  | { type: 'CLEAR_LOCAL_DATA' };

export interface MessageResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}
