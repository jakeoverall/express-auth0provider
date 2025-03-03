const {
  BadRequest,
  Forbidden,
  Unauthorized,
} = require('../lib/Errors.js')

describe('Errors', () => {
  describe('BadRequest', () => {
    test('should create an instance of BadRequest with correct properties', () => {
      const error = new BadRequest('Invalid request');
      expect(error).toBeInstanceOf(BadRequest);
      expect(error.message).toBe('Invalid request');
      expect(error.statusCode).toBe(400);
    });
  });

  describe('Forbidden', () => {
    test('should create an instance of Forbidden with correct properties', () => {
      const error = new Forbidden('Access denied');
      expect(error).toBeInstanceOf(Forbidden);
      expect(error.message).toBe('Access denied');
      expect(error.statusCode).toBe(403);
    });
  });

  describe('Unauthorized', () => {
    test('should create an instance of Unauthorized with correct properties', () => {
      const error = new Unauthorized('Unauthorized access');
      expect(error).toBeInstanceOf(Unauthorized);
      expect(error.message).toBe('Unauthorized access');
      expect(error.statusCode).toBe(401);
    });
  });
});