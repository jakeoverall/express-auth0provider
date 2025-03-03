const { SimpleCache } = require("../lib/SimpleCache.js");

describe("SimpleCache", () => {
  let cache = new SimpleCache();

  test("should set and get a value", () => {
    cache.set("key1", "value1");
    expect(cache.get("key1")).toBe("value1");
  });

  test("should return undefined for a non-existent key", () => {
    expect(cache.get("nonExistentKey")).toBeNull();
  });

  test("should remove a key", () => {
    cache.set("key2", "value2");
    cache.remove("key2");
    expect(cache.get("key2")).toBeNull();
  });

  test("should flush all keys", () => {
    cache.set("key3", "value3");
    cache.flush();
    expect(cache.get("key3")).toBeNull();
  });

  test("should handle multiple keys", () => {
    cache.set("key4", "value4");
    cache.set("key5", "value5");
    expect(cache.get("key4")).toBe("value4");
    expect(cache.get("key5")).toBe("value5");
    cache.remove("key4");
    expect(cache.get("key4")).toBeNull();
    expect(cache.get("key5")).toBe("value5");
    cache.flush();
    expect(cache.get("key5")).toBeNull();
  });

  test("should handle undefined values", () => {
    cache.set("key6", undefined);
    expect(cache.get("key6")).toBeNull();
    cache.remove("key6");
    expect(cache.get("key6")).toBeNull();
  });


  test("it should handle expired keys", async () => {
    cache = new SimpleCache({ stdTTL: 1 });
    cache.set("key7", "value7", 1);
    expect(cache.get("key7")).toBe("value7");
    await new Promise((resolve) => setTimeout(resolve, 1100));
    expect(cache.get("key7")).toBeNull();
  });
})
