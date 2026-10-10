export type MemberStatus = "pending" | "active" | "revoked";
export type CredentialStatus = "pending" | "registered" | "revoked" | "expired";

export interface MemberRecord {
  id: string;
  memberRef: string;
  status: MemberStatus;
  createdAt: string;
  updatedAt: string;
  revokedAt?: string;
  revocationReason?: string;
}

export interface CredentialRecord {
  id: string;
  memberId: string;
  commitment: string;
  status: CredentialStatus;
  createdAt: string;
  updatedAt: string;
  expiresAt?: string;
}

export interface MembershipStatusDTO {
  registered: boolean;
  active: boolean;
  status: MemberStatus | "not_registered";
  credentialRegistered: boolean;
  credentialStatus: CredentialStatus | "none";
  anonymousVerificationReady: boolean;
  expiresAt?: string;
}

export interface EnrollMemberResponse {
  success: boolean;
  membership: {
    status: MemberStatus;
    createdAt: string;
  };
  credential: {
    status: CredentialStatus;
    commitmentReference: string;
    createdAt: string;
    expiresAt: string;
    commitment?: string;
    identitySecretExport?: string;
    root?: string;
  };
}

export interface RevokeMemberResponse {
  success: boolean;
  status: MemberStatus;
  revokedAt: string;
}

export interface ValidateMemberResponse {
  valid: boolean;
  status: MemberStatus | "not_registered";
  active: boolean;
  credentialValid: boolean;
}
