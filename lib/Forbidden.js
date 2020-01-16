export class Forbidden extends Error {
  constructor(msg = "Forbidden") {
    super(msg);
    this.status = 403;
  }
}
