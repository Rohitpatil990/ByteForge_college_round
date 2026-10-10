import {
  AssessmentReport,
  AssessmentSummary,
  ChainVerification,
  Defense,
  Finding,
  Run,
  TargetConfig,
} from './types';

const API_BASE = 'http://127.0.0.1:8000';

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options?.headers || {}),
      },
    });

    if (!res.ok) {
      let errorMsg = `HTTP ${res.status}: ${res.statusText}`;
      try {
        const data = await res.json();
        if (data && data.detail) {
          errorMsg = data.detail;
        }
      } catch {
        // use default errorMsg
      }
      throw new Error(errorMsg);
    }

    return (await res.json()) as T;
  } catch (err: any) {
    if (err.message && err.message.includes('Failed to fetch')) {
      throw new Error('Backend API server unreachable at http://127.0.0.1:8000');
    }
    throw err;
  }
}

export const api = {
  checkHealth: () => request<{ status: string; service: string }>('/health'),
  getTargetConfigs: () => request<TargetConfig[]>('/target/configs'),
  listAssessments: () => request<AssessmentSummary[]>('/assessments'),
  createAssessment: (name?: string, target_id?: string) =>
    request<any>('/assessments', {
      method: 'POST',
      body: JSON.stringify({ name, target_id }),
    }),
  getAssessment: (id: string) => request<any>(`/assessments/${id}`),
  assignTarget: (id: string, target_id: string) =>
    request<{ assessment_id: string; target_id: string; status: string; message: string }>(
      `/assessments/${id}/target`,
      {
        method: 'POST',
        body: JSON.stringify({ target_id }),
      }
    ),
  startRuns: (id: string) =>
    request<{ assessment_id: string; runs_executed: number; runs: Run[] }>(
      `/assessments/${id}/runs`,
      { method: 'POST' }
    ),
  getRuns: (id: string) => request<Run[]>(`/assessments/${id}/runs`),
  getRunDetail: (id: string, run_id: string) =>
    request<Run>(`/assessments/${id}/runs/${run_id}`),
  getFindings: (id: string, source?: string) =>
    request<Finding[]>(`/assessments/${id}/findings${source ? `?source=${source}` : ''}`),
  getDefenses: (id: string) => request<Defense[]>(`/assessments/${id}/defenses`),
  toggleDefense: (id: string, defense_id: string) =>
    request<Defense>(`/assessments/${id}/defenses/${defense_id}/toggle`, { method: 'POST' }),
  challengeDefenses: (id: string) =>
    request<any>(`/assessments/${id}/challenge`, { method: 'POST' }),
  retestAssessment: (id: string) =>
    request<any>(`/assessments/${id}/retest`, { method: 'POST' }),
  getReport: (id: string) => request<AssessmentReport>(`/assessments/${id}/report`),
  verifyChain: (id: string) =>
    request<ChainVerification>(`/assessments/${id}/verify-chain`, { method: 'POST' }),
  runTamperTest: (id: string) =>
    request<{ tamper_detected: boolean; message: string; tampered_index?: number }>(
      `/assessments/${id}/tamper-test`,
      { method: 'POST' }
    ),
  getRecordedFixture: () => request<any>('/recorded/runs'),
};
