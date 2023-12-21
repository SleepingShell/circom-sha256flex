import path = require('path');

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex as toHex } from '@noble/hashes/utils';
import { expect } from 'chai';
const circom_tester = require('circom_tester');
const wasm_tester = circom_tester.wasm;

function bufferTobitArray(b: Buffer) {
  const res = [];
  for (let i=0; i<b.length; i++) {
      for (let j=0; j<8; j++) {
          res.push((b[i] >> (7-j) &1));
      }
  }
  return res;
}

function bitArrayTobuffer(a: number[] | bigint[]) {
  const len = Math.floor((a.length -1 )/8)+1;
  const b = Buffer.alloc(len);

  for (let i=0; i<a.length; i++) {
      const p = Math.floor(i/8);
      b[p] = b[p] | (Number(a[i]) << ( 7 - (i%8)  ));
  }
  return b;
}

function bufferToBigIntArray(arr: Buffer): bigint[] {
  let res: bigint[] = [];
  arr.forEach((x) => res.push(BigInt(x)));

  return res;
}

describe.only('Flexible sha256 circuit', async () => {
  let sha_circuit: any;
  before(async () => {
    sha_circuit = await wasm_tester(path.join(__dirname, 'test_sha256flex_512.circom'));
  })

  it('Sha256_512', async () => {
    let input = Buffer.alloc(64).fill(0);
    input[0] = 1;
    let witness = await sha_circuit.calculateWitness({in: bufferToBigIntArray(Buffer.from(bufferTobitArray(input))), in_num_bits: 8});
    expect(bitArrayTobuffer(witness.slice(1,257)).toString('hex')).eq(toHex(sha256(Buffer.from([1]))));

    input[1] = 3;
    witness = await sha_circuit.calculateWitness({in: bufferToBigIntArray(Buffer.from(bufferTobitArray(input))), in_num_bits: 16});
    expect(bitArrayTobuffer(witness.slice(1,257)).toString('hex')).eq(toHex(sha256(Buffer.from([1,3]))));
  });
})