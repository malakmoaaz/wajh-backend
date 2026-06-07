export function errorHandler(err, req, res, next) {
  console.error(`[${new Date().toISOString()}] ${err.message}`, err.stack);

  const status = err.status || err.statusCode || 500;

  res.status(status).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
}

// Wraps async route handlers so unhandled promise rejections are caught
export function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}