class Unauthorized extends Error {
  constructor(msg = 'Unauthorized') {
    super(msg);
    this.name = this.constructor.name;
    this.status = 401;
  }
}

class Forbidden extends Error {
  constructor(msg = 'Forbidden') {
    super(msg);
    this.name = this.constructor.name;
    this.status = 403;
  }
}

class BadRequest extends Error {
  constructor(msg = 'Bad Request') {
    super(msg);
    this.name = this.constructor.name;
    this.status = 400;
  }
}

module.exports = { Unauthorized, Forbidden, BadRequest };