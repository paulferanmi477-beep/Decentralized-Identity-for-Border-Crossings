import { describe, it, expect, beforeEach } from "vitest";
import { Cl, ClarityValue, stringUtf8CV, buffCV, uintCV, principalCV, listCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_DUPLICATE_IDENTITY = 101;
const ERR_INVALID_HASH = 102;
const ERR_INVALID_PUBLIC_KEY = 103;
const ERR_INVALID_NAME = 104;
const ERR_INVALID_BIOMETRIC = 105;
const ERR_INVALID_TIMESTAMP = 106;
const ERR_IDENTITY_NOT_FOUND = 107;
const ERR_INVALID_RECOVERY_CONTACTS = 108;
const ERR_RECOVERY_ALREADY_INITIATED = 109;
const ERR_RECOVERY_NOT_INITIATED = 110;
const ERR_INVALID_APPROVAL_COUNT = 111;
const ERR_AUTHORITY_NOT_VERIFIED = 114;
const ERR_MAX_IDENTITIES_EXCEEDED = 115;

interface Identity {
  identityHash: Buffer;
  publicKey: Buffer;
  name: string;
  biometricHash: Buffer;
  timestamp: number;
  creator: string;
  status: boolean;
  recoveryContacts: string[];
  recoveryThreshold: number;
  recoveryInitiated: boolean;
  recoveryApprovals: string[];
}

interface IdentityUpdate {
  updateName: string;
  updateTimestamp: number;
  updater: string;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class IdentityRegistryMock {
  state: {
    nextIdentityId: number;
    maxIdentities: number;
    authorityContract: string | null;
    identities: Map<number, Identity>;
    identitiesByHash: Map<string, number>;
    identityUpdates: Map<number, IdentityUpdate>;
  } = {
    nextIdentityId: 0,
    maxIdentities: 1000000,
    authorityContract: null,
    identities: new Map(),
    identitiesByHash: new Map(),
    identityUpdates: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1USER";
  authorities: Set<string> = new Set(["ST1USER", "ST2REC1", "ST3REC2", "ST4REC3"]);

  reset() {
    this.state = {
      nextIdentityId: 0,
      maxIdentities: 1000000,
      authorityContract: null,
      identities: new Map(),
      identitiesByHash: new Map(),
      identityUpdates: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1USER";
    this.authorities = new Set(["ST1USER", "ST2REC1", "ST3REC2", "ST4REC3"]);
  }

  setAuthorityContract(contractPrincipal: string): Result<boolean> {
    if (contractPrincipal === "SP000000000000000000002Q6VF78") return { ok: false, value: false };
    if (this.state.authorityContract !== null) return { ok: false, value: false };
    this.state.authorityContract = contractPrincipal;
    return { ok: true, value: true };
  }

  registerIdentity(
    identityHash: Buffer,
    publicKey: Buffer,
    name: string,
    biometricHash: Buffer,
    recoveryContacts: string[],
    recoveryThreshold: number
  ): Result<number> {
    if (this.state.nextIdentityId >= this.state.maxIdentities) return { ok: false, value: ERR_MAX_IDENTITIES_EXCEEDED };
    if (identityHash.length !== 32) return { ok: false, value: ERR_INVALID_HASH };
    if (publicKey.length !== 33) return { ok: false, value: ERR_INVALID_PUBLIC_KEY };
    if (!name || name.length > 100) return { ok: false, value: ERR_INVALID_NAME };
    if (biometricHash.length !== 32) return { ok: false, value: ERR_INVALID_BIOMETRIC };
    if (recoveryContacts.length < 2 || recoveryContacts.length > 5) return { ok: false, value: ERR_INVALID_RECOVERY_CONTACTS };
    if (recoveryThreshold < 1 || recoveryThreshold > recoveryContacts.length) return { ok: false, value: ERR_INVALID_APPROVAL_COUNT };
    if (this.state.identitiesByHash.has(identityHash.toString("hex"))) return { ok: false, value: ERR_DUPLICATE_IDENTITY };
    if (!this.state.authorityContract) return { ok: false, value: ERR_AUTHORITY_NOT_VERIFIED };

    const id = this.state.nextIdentityId;
    const identity: Identity = {
      identityHash,
      publicKey,
      name,
      biometricHash,
      timestamp: this.blockHeight,
      creator: this.caller,
      status: true,
      recoveryContacts,
      recoveryThreshold,
      recoveryInitiated: false,
      recoveryApprovals: [],
    };
    this.state.identities.set(id, identity);
    this.state.identitiesByHash.set(identityHash.toString("hex"), id);
    this.state.nextIdentityId++;
    return { ok: true, value: id };
  }

  updateIdentity(id: number, newName: string): Result<boolean> {
    const identity = this.state.identities.get(id);
    if (!identity) return { ok: false, value: false };
    if (identity.creator !== this.caller) return { ok: false, value: false };
    if (!newName || newName.length > 100) return { ok: false, value: false };
    const updated: Identity = { ...identity, name: newName, timestamp: this.blockHeight };
    this.state.identities.set(id, updated);
    this.state.identityUpdates.set(id, { updateName: newName, updateTimestamp: this.blockHeight, updater: this.caller });
    return { ok: true, value: true };
  }

  initiateRecovery(id: number): Result<boolean> {
    const identity = this.state.identities.get(id);
    if (!identity) return { ok: false, value: false };
    if (identity.creator !== this.caller) return { ok: false, value: false };
    if (identity.recoveryInitiated) return { ok: false, value: false };
    const updated: Identity = { ...identity, recoveryInitiated: true };
    this.state.identities.set(id, updated);
    return { ok: true, value: true };
  }

  approveRecovery(id: number): Result<boolean> {
    const identity = this.state.identities.get(id);
    if (!identity) return { ok: false, value: false };
    if (!identity.recoveryInitiated) return { ok: false, value: false };
    if (!identity.recoveryContacts.includes(this.caller)) return { ok: false, value: false };
    const approvals = [...identity.recoveryApprovals, this.caller];
    if (approvals.length > 5) return { ok: false, value: false };
    const updated: Identity = { ...identity, recoveryApprovals: approvals };
    this.state.identities.set(id, updated);
    return { ok: true, value: true };
  }

  completeRecovery(id: number, newPublicKey: Buffer): Result<boolean> {
    const identity = this.state.identities.get(id);
    if (!identity) return { ok: false, value: false };
    if (!identity.recoveryInitiated) return { ok: false, value: false };
    if (identity.recoveryApprovals.length < identity.recoveryThreshold) return { ok: false, value: false };
    if (newPublicKey.length !== 33) return { ok: false, value: false };
    const updated: Identity = { ...identity, publicKey: newPublicKey, timestamp: this.blockHeight, creator: this.caller, recoveryInitiated: false, recoveryApprovals: [] };
    this.state.identities.set(id, updated);
    return { ok: true, value: true };
  }

  getIdentity(id: number): Identity | null {
    return this.state.identities.get(id) || null;
  }

  getIdentityByHash(hash: Buffer): Identity | null {
    const id = this.state.identitiesByHash.get(hash.toString("hex"));
    return id !== undefined ? this.state.identities.get(id) || null : null;
  }
}

describe("IdentityRegistry", () => {
  let contract: IdentityRegistryMock;
  const identityHash = Buffer.alloc(32, 1);
  const publicKey = Buffer.alloc(33, 2);
  const biometricHash = Buffer.alloc(32, 3);
  const recoveryContacts = ["ST2REC1", "ST3REC2", "ST4REC3"];
  const newPublicKey = Buffer.alloc(33, 4);

  beforeEach(() => {
    contract = new IdentityRegistryMock();
    contract.reset();
  });

  it("registers an identity successfully", () => {
    contract.setAuthorityContract("ST2AUTH");
    const result = contract.registerIdentity(identityHash, publicKey, "Alice", biometricHash, recoveryContacts, 2);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);
    const identity = contract.getIdentity(0);
    expect(identity?.name).toBe("Alice");
    expect(identity?.identityHash).toBe(identityHash);
    expect(identity?.publicKey).toBe(publicKey);
    expect(identity?.biometricHash).toBe(biometricHash);
    expect(identity?.recoveryContacts).toEqual(recoveryContacts);
    expect(identity?.recoveryThreshold).toBe(2);
    expect(contract.getIdentityByHash(identityHash)).toBe(identity);
  });

  it("rejects duplicate identity hash", () => {
    contract.setAuthorityContract("ST2AUTH");
    contract.registerIdentity(identityHash, publicKey, "Alice", biometricHash, recoveryContacts, 2);
    const result = contract.registerIdentity(identityHash, Buffer.alloc(33, 5), "Bob", biometricHash, recoveryContacts, 2);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_DUPLICATE_IDENTITY);
  });

  it("rejects invalid hash length", () => {
    contract.setAuthorityContract("ST2AUTH");
    const result = contract.registerIdentity(Buffer.alloc(31), publicKey, "Alice", biometricHash, recoveryContacts, 2);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_HASH);
  });

  it("rejects invalid public key length", () => {
    contract.setAuthorityContract("ST2AUTH");
    const result = contract.registerIdentity(identityHash, Buffer.alloc(34), "Alice", biometricHash, recoveryContacts, 2);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_PUBLIC_KEY);
  });

  it("rejects invalid name", () => {
    contract.setAuthorityContract("ST2AUTH");
    const result = contract.registerIdentity(identityHash, publicKey, "", biometricHash, recoveryContacts, 2);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_NAME);
  });

  it("rejects invalid biometric hash", () => {
    contract.setAuthorityContract("ST2AUTH");
    const result = contract.registerIdentity(identityHash, publicKey, "Alice", Buffer.alloc(31), recoveryContacts, 2);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_BIOMETRIC);
  });

  it("rejects invalid recovery contacts", () => {
    contract.setAuthorityContract("ST2AUTH");
    const result = contract.registerIdentity(identityHash, publicKey, "Alice", biometricHash, ["ST2REC1"], 2);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_RECOVERY_CONTACTS);
  });

  it("rejects invalid recovery threshold", () => {
    contract.setAuthorityContract("ST2AUTH");
    const result = contract.registerIdentity(identityHash, publicKey, "Alice", biometricHash, recoveryContacts, 4);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_APPROVAL_COUNT);
  });

  it("rejects registration without authority contract", () => {
    const result = contract.registerIdentity(identityHash, publicKey, "Alice", biometricHash, recoveryContacts, 2);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_AUTHORITY_NOT_VERIFIED);
  });

  it("updates identity successfully", () => {
    contract.setAuthorityContract("ST2AUTH");
    contract.registerIdentity(identityHash, publicKey, "Alice", biometricHash, recoveryContacts, 2);
    const result = contract.updateIdentity(0, "Alicia");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const identity = contract.getIdentity(0);
    expect(identity?.name).toBe("Alicia");
    const update = contract.state.identityUpdates.get(0);
    expect(update?.updateName).toBe("Alicia");
  });

  it("rejects update by non-creator", () => {
    contract.setAuthorityContract("ST2AUTH");
    contract.registerIdentity(identityHash, publicKey, "Alice", biometricHash, recoveryContacts, 2);
    contract.caller = "ST2REC1";
    const result = contract.updateIdentity(0, "Alicia");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("initiates recovery successfully", () => {
    contract.setAuthorityContract("ST2AUTH");
    contract.registerIdentity(identityHash, publicKey, "Alice", biometricHash, recoveryContacts, 2);
    const result = contract.initiateRecovery(0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const identity = contract.getIdentity(0);
    expect(identity?.recoveryInitiated).toBe(true);
  });

  it("rejects recovery initiation by non-creator", () => {
    contract.setAuthorityContract("ST2AUTH");
    contract.registerIdentity(identityHash, publicKey, "Alice", biometricHash, recoveryContacts, 2);
    contract.caller = "ST2REC1";
    const result = contract.initiateRecovery(0);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(false);
  });

  it("approves recovery successfully", () => {
    contract.setAuthorityContract("ST2AUTH");
    contract.registerIdentity(identityHash, publicKey, "Alice", biometricHash, recoveryContacts, 2);
    contract.initiateRecovery(0);
    contract.caller = "ST2REC1";
    const result = contract.approveRecovery(0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const identity = contract.getIdentity(0);
    expect(identity?.recoveryApprovals).toContain("ST2REC1");
  });

  it("completes recovery successfully", () => {
    contract.setAuthorityContract("ST2AUTH");
    contract.registerIdentity(identityHash, publicKey, "Alice", biometricHash, recoveryContacts, 2);
    contract.initiateRecovery(0);
    contract.caller = "ST2REC1";
    contract.approveRecovery(0);
    contract.caller = "ST3REC2";
    contract.approveRecovery(0);
    contract.caller = "ST1USER";
    const result = contract.completeRecovery(0, newPublicKey);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const identity = contract.getIdentity(0);
    expect(identity?.publicKey).toBe(newPublicKey);
    expect(identity?.recoveryInitiated).toBe(false);
    expect(identity?.recoveryApprovals).toEqual([]);
  });
});