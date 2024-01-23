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
  let sha_circuit_bits: any;
  let sha_circuit_bytes: any;
  let sha_circuit_bytes_256: any;
  before(async () => {
    sha_circuit_bits = await wasm_tester(path.join(__dirname, 'test_sha256flex_512.circom'));
    sha_circuit_bytes = await wasm_tester(path.join(__dirname, 'test_sha256flexbytes.circom'));
    sha_circuit_bytes_256 = await wasm_tester(path.join(__dirname, 'test_sha256flexbytes_256.circom'));
  })

  it('Sha256 512 bits', async () => {
    let input = Buffer.alloc(64).fill(0);
    input[0] = 1;
    let witness = await sha_circuit_bits.calculateWitness({in: bufferToBigIntArray(Buffer.from(bufferTobitArray(input))), in_num_bits: 8});
    expect(bitArrayTobuffer(witness.slice(1,257)).toString('hex')).eq(toHex(sha256(Buffer.from([1]))));

    input[1] = 3;
    witness = await sha_circuit_bits.calculateWitness({in: bufferToBigIntArray(Buffer.from(bufferTobitArray(input))), in_num_bits: 16});
    expect(bitArrayTobuffer(witness.slice(1,257)).toString('hex')).eq(toHex(sha256(Buffer.from([1,3]))));
  });

  it('Sha256 64 bytes', async () => {
    let input = Buffer.alloc(64).fill(0);
    input[0] = 1;
    let witness = await sha_circuit_bytes.calculateWitness({in: bufferToBigIntArray(input), in_num_bytes: 1});
    expect(bitArrayTobuffer(witness.slice(1,257)).toString('hex')).eq(toHex(sha256(Buffer.from([1]))));

    input[1] = 3;
    witness = await sha_circuit_bytes.calculateWitness({in: bufferToBigIntArray(input), in_num_bytes: 2});
    expect(bitArrayTobuffer(witness.slice(1,257)).toString('hex')).eq(toHex(sha256(Buffer.from([1,3]))));
  });

  it('Sha256 256 bytes', async () => {
    let input = Buffer.alloc(256).fill(0);
    input[199] = 10;
    let witness = await sha_circuit_bytes_256.calculateWitness({in: bufferToBigIntArray(input), in_num_bytes: 200});
    expect(bitArrayTobuffer(witness.slice(1,257)).toString('hex')).eq(toHex(sha256(input.subarray(0,200))));
  });

  it.only('Sha256 clientDataJSON example', async () => {
    let data = Buffer.from("eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSHg0ZEhCc2FHUmdYRmhVVUV4SVJFQThPRFF3TENna0lCd1lGQkFNQ0FRQSIsIm9yaWdpbiI6Imh0dHBzOi8vZ3JhbXRoYW5vcy5naXRodWIuaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2UsInZpcnR1YWxfYXV0aGVudGljYXRvciI6IkdyYW1UaGFub3MgJiBVbml2ZXJzaXR5IG9mIFBpcmFldXMifQ", "base64");
    let input = Buffer.concat([data], 256);
    let witness = await sha_circuit_bytes_256.calculateWitness({in: bufferToBigIntArray(input), in_num_bytes: data.length});

    expect(bitArrayTobuffer(witness.slice(1,257)).toString('hex')).eq(toHex(sha256(data)));
  });
})