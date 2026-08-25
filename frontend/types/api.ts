export type Severity='CRITICAL'|'HIGH'|'MEDIUM'|'LOW';
export type IncidentStatus='NEW'|'INVESTIGATING'|'CONTAINED'|'RESOLVED'|'CLOSED';
export interface Incident {incident_id:string;title:string;description:string;severity:Severity;status:IncidentStatus;version:number;created_at:string;updated_at:string;source_ip?:string;destination_ip?:string;triggering_detection_ids:string[];context:Record<string,unknown>}
export interface DetectionRule {rule_id:string;rule_name:string;description?:string;severity:string;enabled:boolean;parameters:Record<string,unknown>;created_at:string;updated_at:string}
