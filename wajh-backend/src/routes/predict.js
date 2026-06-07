import { Router } from 'express';
import { requireAuth, requireRole } from '../middleware/auth.js';
import { asyncHandler } from '../middleware/errorHandler.js';
import prisma from '../lib/prisma.js';

const router = Router();

const ML_API_URL = process.env.ML_API_URL;
const ML_TIMEOUT_MS = 30000;

async function callMLService(payload, retries = 2) {
  let lastError;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), ML_TIMEOUT_MS);

      const response = await fetch(`${ML_API_URL}/ml/predict`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        const text = await response.text();
        throw new Error(`ML service error ${response.status}: ${text}`);
      }

      return await response.json();
    } catch (err) {
      lastError = err;
      if (attempt < retries) {
        await new Promise((r) => setTimeout(r, 1000 * (attempt + 1)));
      }
    }
  }

  throw lastError;
}

// POST /api/predict
// Requires authentication. DOCTOR role can run predictions.
router.post(
  '/',
  requireAuth,
  requireRole('DOCTOR'),
  asyncHandler(async (req, res) => {
    const { landmarks, imageQuality, poseData } = req.body;

    if (!landmarks || !Array.isArray(landmarks)) {
      return res.status(400).json({ error: 'landmarks array is required' });
    }

    // Call ML service — backend holds the ML_API_URL, never exposed to client
    let mlResult;
    try {
      mlResult = await callMLService({ landmarks, imageQuality, poseData });
    } catch (err) {
      console.error('ML service failed:', err.message);
      return res.status(502).json({
        error: 'Prediction service temporarily unavailable. Please try again.',
      });
    }

    // Save to DB — backend is source of truth, not frontend
    const prediction = await prisma.prediction.create({
      data: {
        result: JSON.stringify(mlResult.procedure ?? mlResult),
        confidence: mlResult.confidence ?? 0,
        userId: req.user.id,
      },
    });

    res.json({
      prediction: {
        id: prediction.id,
        result: mlResult,
        confidence: prediction.confidence,
        createdAt: prediction.createdAt,
      },
    });
  })
);

// GET /api/predict/history — prediction history for current user
router.get(
  '/history',
  requireAuth,
  asyncHandler(async (req, res) => {
    const predictions = await prisma.prediction.findMany({
      where: { userId: req.user.id },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });

    res.json({
      predictions: predictions.map((p) => ({
        id: p.id,
        result: JSON.parse(p.result),
        confidence: p.confidence,
        createdAt: p.createdAt,
      })),
    });
  })
);

export default router;