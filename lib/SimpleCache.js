class SimpleCache {
  constructor(options = {}) {
    this.cache = {};
    this.ttl = options.stdTTL || 60 * 60 * 1; // default to 1 hour
    this.expiryTimes = {};
  }

  get(key) {
    if (this.isExpired(key)) {
      delete this.cache[key];
      delete this.expiryTimes[key];
      return null;
    }
    return this.cache[key];
  }

  set(key, value) {
    if (!key) {
      return
    }
    if (value === undefined) {
      this.remove(key);
      return;
    }
    this.cache[key] = value;
    this.expiryTimes[key] = Date.now() + this.ttl * 1000;
  }

  isExpired(key) {
    return !this.expiryTimes[key] || Date.now() > this.expiryTimes[key];
  }

  remove(key) {
    delete this.cache[key];
    delete this.expiryTimes[key];
  }

  flush() {
    this.cache = {};
    this.expiryTimes = {};
  }
}
exports.SimpleCache = SimpleCache;
