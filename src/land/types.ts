export interface TitleBody {
  v: 1;
  parcelId: string; // example format: KTM-W10-K1234 (district-ward-kitta)
  seq: number; // 0 for the first issuance, +1 per transfer
  prevHash: string | null; // SHA-256 (hex) of the previous TitleBody, canonicalised
  ownerSerial: string; // citizen certificate serial
  ownerId: string;
  areaSqm: number;
  issuedAt: string;
  issuerSerial: string; // LRO officer certificate serial
  evidenceHash: string | null; // SHA-256 of the transfer intent + acceptance bodies (null at issuance)
}

export interface Title {
  body: TitleBody;
  signature: string; // LRO officer signature over the canonical body
}

export interface TransferIntentBody {
  v: 1;
  parcelId: string;
  titleHash: string; // hash of the exact title version being sold (stops double sale)
  sellerSerial: string;
  buyerSerial: string;
  nonce: string; // 128-bit random hex, single use
  issuedAt: string;
  expiresAt: string;
}

export interface TransferIntent {
  body: TransferIntentBody;
  signature: string; // seller
}

export interface AcceptanceBody {
  v: 1;
  intentHash: string;
  buyerSerial: string;
  acceptedAt: string;
}

export interface TransferAcceptance {
  body: AcceptanceBody;
  signature: string; // buyer
}

export interface TransferEvidence {
  intent: TransferIntent;
  acceptance: TransferAcceptance;
}

/** One link of a parcel's history: the LRO-signed title plus the signed consent that justifies it. */
export interface TitleRecord {
  title: Title;
  evidence: TransferEvidence | null;
}
