import { describe, expect, it } from "vitest";
import { bytesEqual, concatBytes, fromBase64Url, fromHex, toBase64Url, toHex, utf8, fromUtf8 } from "../src/crypto/bytes";
import { canonicalize } from "../src/crypto/canonical";
import { randomBytes } from "../src/crypto/primitives";

describe("bytes", () => {
  it("base64url round-trips for every length 0..64", () => {
    for (let n = 0; n <= 64; n++) {
      const data = randomBytes(n);
      expect(bytesEqual(fromBase64Url(toBase64Url(data)), data)).toBe(true);
    }
  });

  it("base64url uses the URL alphabet without padding", () => {
    expect(toBase64Url(new Uint8Array([0xfb, 0xff, 0xfe]))).toBe("-__-");
    expect(toBase64Url(utf8("a"))).toBe("YQ");
  });

  it.each(["a+b", "a/b", "ab=", "a b", "A"])("rejects invalid base64url %j", (bad) => {
    expect(() => fromBase64Url(bad)).toThrow();
  });

  it("hex round-trips and rejects bad input", () => {
    expect(toHex(fromHex("00ff10"))).toBe("00ff10");
    expect(() => fromHex("abc")).toThrow();
    expect(() => fromHex("zz")).toThrow();
  });

  it("utf8 round-trips, concat and compare behave", () => {
    expect(fromUtf8(utf8("भूमि"))).toBe("भूमि");
    expect(concatBytes(utf8("ab"), utf8("c"))).toEqual(utf8("abc"));
    expect(bytesEqual(utf8("abc"), utf8("abd"))).toBe(false);
    expect(bytesEqual(utf8("abc"), utf8("ab"))).toBe(false);
    expect(() => fromUtf8(new Uint8Array([0xff, 0xfe]))).toThrow();
  });
});

describe("canonicalize", () => {
  it("is independent of key order and nesting order", () => {
    expect(canonicalize({ b: 1, a: { d: 2, c: 3 } })).toBe(canonicalize({ a: { c: 3, d: 2 }, b: 1 }));
  });

  it("produces the exact expected string", () => {
    expect(canonicalize({ b: [1, "x", null, true], a: "é" })).toBe('{"a":"é","b":[1,"x",null,true]}');
  });

  it("keeps array order", () => {
    expect(canonicalize([2, 1])).not.toBe(canonicalize([1, 2]));
  });

  it.each([
    ["undefined value", { a: undefined }],
    ["NaN", { a: Number.NaN }],
    ["Infinity", { a: Number.POSITIVE_INFINITY }],
    ["float", { a: 1.5 }],
    ["unsafe integer", { a: 2 ** 60 }],
    ["function", { a: () => 1 }],
    ["bigint", { a: 1n }],
  ])("rejects %s", (_name, value) => {
    expect(() => canonicalize(value)).toThrow();
  });
});
