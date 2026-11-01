import { fromUtf8, readU16, readU32, u32be, utf8 } from "./bytes";

export const RECORD = {
  heartbeat: 1,
  data: 2,
  open: 3,
  close: 4,
  credit: 5,
  rekey: 6,
} as const;

export type DecodedRecord = {
  type: number;
  conn: number;
  seq: number;
  payload: Uint8Array;
};

export function encodeRecord(type: number, conn: number, seq: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(11 + payload.length);
  out[0] = type & 0xff;
  out.set(u32be(conn), 1);
  out.set(u32be(seq), 5);
  out[9] = (payload.length >> 8) & 0xff;
  out[10] = payload.length & 0xff;
  out.set(payload, 11);
  return out;
}

export function decodeRecord(frame: Uint8Array): DecodedRecord {
  if (frame.length < 11) throw new Error("内层帧过短");
  const len = readU16(frame, 9);
  if (frame.length < 11 + len) throw new Error("内层帧被截断");
  return {
    type: frame[0],
    conn: readU32(frame, 1),
    seq: readU32(frame, 5),
    payload: frame.slice(11, 11 + len),
  };
}

export function recordLabel(type: number): string {
  switch (type) {
    case RECORD.heartbeat:
      return "心跳";
    case RECORD.data:
      return "数据";
    case RECORD.open:
      return "打开";
    case RECORD.close:
      return "关闭";
    case RECORD.credit:
      return "信用";
    case RECORD.rekey:
      return "换钥";
    default:
      return "未知";
  }
}

export function payloadText(payload: Uint8Array): string {
  return fromUtf8(payload);
}

export function heartbeatPayload(now = Date.now()): Uint8Array {
  return utf8(`hb ${now}`);
}
