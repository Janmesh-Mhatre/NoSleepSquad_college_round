import crypto from "node:crypto";

export interface MerkleProof {
  leaf: string;
  leafIndex: number;
  siblings: string[];
  root: string;
}

/**
 * Robust Pairwise Cryptographic Merkle Tree
 * Conforms to canonical binary Merkle tree specification with pairwise SHA-256.
 */
export class MerkleTree {
  private leaves: string[];
  private layers: string[][];

  constructor(leaves: string[]) {
    if (!leaves || leaves.length === 0) {
      throw new Error("Cannot construct Merkle tree with zero leaves.");
    }

    // Canonical sorting of raw leaves
    this.leaves = [...leaves].sort();
    this.layers = this.buildLayers(this.leaves);
  }

  private hashPair(left: string, right: string): string {
    return crypto
      .createHash("sha256")
      .update(`INCOGNITO-MERKLE-PAIR:${left}:${right}`)
      .digest("hex");
  }

  private buildLayers(leaves: string[]): string[][] {
    const layers: string[][] = [leaves];
    let current = leaves;

    while (current.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < current.length; i += 2) {
        const left = current[i];
        // If odd node, duplicate the last node
        const right = i + 1 < current.length ? current[i + 1] : left;
        next.push(this.hashPair(left, right));
      }
      layers.push(next);
      current = next;
    }

    return layers;
  }

  getRoot(): string {
    return this.layers[this.layers.length - 1][0];
  }

  getBytes32Root(): string {
    return "0x" + this.getRoot();
  }

  getProof(leafIndex: number): MerkleProof {
    if (leafIndex < 0 || leafIndex >= this.leaves.length) {
      throw new Error(`Leaf index ${leafIndex} out of bounds.`);
    }

    const siblings: string[] = [];
    let idx = leafIndex;

    for (let layerIdx = 0; layerIdx < this.layers.length - 1; layerIdx++) {
      const layer = this.layers[layerIdx];
      const isRight = idx % 2 === 1;
      const siblingIdx = isRight ? idx - 1 : idx + 1;
      const sibling = siblingIdx < layer.length ? layer[siblingIdx] : layer[idx];
      siblings.push(sibling);
      idx = Math.floor(idx / 2);
    }

    return {
      leaf: this.leaves[leafIndex],
      leafIndex,
      siblings,
      root: this.getRoot(),
    };
  }

  static verifyProof(proof: MerkleProof): boolean {
    let current = proof.leaf;
    let idx = proof.leafIndex;

    for (const sibling of proof.siblings) {
      const isRight = idx % 2 === 1;
      const left = isRight ? sibling : current;
      const right = isRight ? current : sibling;
      current = crypto
        .createHash("sha256")
        .update(`INCOGNITO-MERKLE-PAIR:${left}:${right}`)
        .digest("hex");
      idx = Math.floor(idx / 2);
    }

    return current === proof.root;
  }
}
