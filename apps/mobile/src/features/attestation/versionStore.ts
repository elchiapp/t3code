import * as SecureStore from "expo-secure-store";
import * as Schema from "effect/Schema";
import { DeviceVersionDecisionRecord } from "@t3tools/contracts";

const key = "t3-attested-version-decisions-v1";
const decode = Schema.decodeUnknownSync(
  Schema.Struct({
    version: Schema.Literal(1),
    decisions: Schema.Array(DeviceVersionDecisionRecord),
  }),
);

export const mobileVersionStore = {
  async read(): Promise<ReadonlyArray<DeviceVersionDecisionRecord>> {
    const value = await SecureStore.getItemAsync(key);
    if (value === null) return [];
    const result = decode(JSON.parse(value));
    if (result.decisions.length > 32) throw new Error("Too many saved build decisions.");
    return result.decisions;
  },
  async write(decisions: ReadonlyArray<DeviceVersionDecisionRecord>) {
    decode({ version: 1, decisions });
    if (decisions.length > 32) throw new Error("Too many saved build decisions.");
    await SecureStore.setItemAsync(key, JSON.stringify({ version: 1, decisions }), {
      keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  },
};
