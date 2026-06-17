import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 4000;

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use(cors({
  origin: [
    'https://wajh-frontend.vercel.app',
    'https://wajh-web.vercel.app',
    'http://localhost:5173',
    'http://localhost:3000',
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

app.use(express.json({ limit: '50mb' }));
app.use(cookieParser());

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
const authenticateToken = (req, res, next) => {
  const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// ── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/', (_, res) => res.json({ status: 'ok' }));
app.get('/api/health', (_, res) => res.json({ status: 'ok' }));

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, role = 'DOCTOR' } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required' });

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing)
      return res.status(409).json({ error: 'Email already in use' });

    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, password: hashed, role },
    });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(201).json({
      message: 'Registered successfully',
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'Email and password are required' });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({
      message: 'Logged in successfully',
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, secure: true, sameSite: 'none' });
  return res.status(200).json({ message: 'Logged out' });
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({
      where: { id: req.user.id },
      select: { id: true, email: true, role: true },
    });
    return res.json(user);
  } catch (err) {
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ── PATIENTS ──────────────────────────────────────────────────────────────────
app.post('/api/patients', async (req, res) => {
  try {
    const { firstName, lastName, dateOfBirth, gender, notes, phone, email } = req.body;
    if (!firstName || !lastName)
      return res.status(400).json({ message: 'firstName and lastName are required' });
    const patient = await prisma.patient.create({
      data: { firstName, lastName, dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : null, gender, notes, phone, email }
    });
    res.status(201).json(patient);
  } catch (e) { res.status(400).json({ message: e.message }); }
});

app.get('/api/patients', async (_, res) => {
  try {
    const patients = await prisma.patient.findMany({
      orderBy: { createdAt: 'desc' },
      include: { _count: { select: { cases: true } } }
    });
    res.json(patients);
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/patients/:id', async (req, res) => {
  try {
    const patient = await prisma.patient.findUniqueOrThrow({
      where: { id: req.params.id },
      include: {
        cases: {
          orderBy: { createdAt: 'desc' },
          include: { _count: { select: { simulations: true } } }
        }
      }
    });
    res.json(patient);
  } catch (e) { res.status(404).json({ message: 'Patient not found' }); }
});

app.put('/api/patients/:id', async (req, res) => {
  try {
    const { firstName, lastName, dateOfBirth, gender, notes, phone, email } = req.body;
    const patient = await prisma.patient.update({
      where: { id: req.params.id },
      data: { firstName, lastName, dateOfBirth: dateOfBirth ? new Date(dateOfBirth) : null, gender, notes, phone, email }
    });
    res.json(patient);
  } catch (e) { res.status(400).json({ message: e.message }); }
});

app.delete('/api/patients/:id', async (req, res) => {
  try {
    await prisma.patient.delete({ where: { id: req.params.id } });
    res.json({ message: 'Patient deleted' });
  } catch (e) { res.status(400).json({ message: e.message }); }
});

// ── CASES ─────────────────────────────────────────────────────────────────────
app.post('/api/cases', async (req, res) => {
  try {
    const c = await prisma.case.create({ data: req.body });
    res.status(201).json(c);
  } catch (e) { res.status(400).json({ message: e.message }); }
});

app.get('/api/cases', async (req, res) => {
  try {
    const where = req.query.patientId ? { patientId: req.query.patientId } : {};
    const cases = await prisma.case.findMany({
      where, orderBy: { createdAt: 'desc' },
      include: {
        patient: { select: { firstName: true, lastName: true } },
        _count: { select: { simulations: true } }
      }
    });
    res.json(cases);
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/cases/:id', async (req, res) => {
  try {
    const c = await prisma.case.findUniqueOrThrow({
      where: { id: req.params.id },
      include: { patient: true, simulations: { orderBy: { createdAt: 'desc' } } }
    });
    res.json(c);
  } catch (e) { res.status(404).json({ message: 'Case not found' }); }
});

// ── SIMULATIONS ───────────────────────────────────────────────────────────────
app.post('/api/simulations', async (req, res) => {
  try {
    const { caseId, surgeryName, confidence, initialLandmarks, modifiedLandmarks, surgicalPlan, resultImageData, aiRecommendation, goldenRatioData, mlProcedure, mlConfidence } = req.body;
    const sim = await prisma.simulation.create({
      data: { caseId, surgeryName, confidence, initialLandmarks, modifiedLandmarks, surgicalPlan, resultImageData, aiRecommendation, goldenRatioData, mlProcedure, mlConfidence }
    });
    res.status(201).json(sim);
  } catch (e) { res.status(400).json({ message: e.message }); }
});

app.get('/api/simulations', async (req, res) => {
  try {
    const where = req.query.caseId ? { caseId: req.query.caseId } : {};
    const sims = await prisma.simulation.findMany({
      where, orderBy: { createdAt: 'desc' },
      select: { id: true, surgeryName: true, confidence: true, mlProcedure: true, mlConfidence: true, createdAt: true, caseId: true }
    });
    res.json(sims);
  } catch (e) { res.status(500).json({ message: e.message }); }
});

app.get('/api/simulations/:id', async (req, res) => {
  try {
    const sim = await prisma.simulation.findUniqueOrThrow({ where: { id: req.params.id } });
    res.json(sim);
  } catch (e) { res.status(404).json({ message: 'Simulation not found' }); }
});

// ── ANALYZE ───────────────────────────────────────────────────────────────────
function buildDeltas(initial, modified, pxPerMm) {
  return initial.map((before, i) => {
    const after = modified[i] ?? before;
    const dxPx = after.x - before.x;
    const dyPx = after.y - before.y;
    const dxMm = pxPerMm ? dxPx / pxPerMm : dxPx;
    const dyMm = pxPerMm ? dyPx / pxPerMm : dyPx;
    return {
      id: before.id, name: before.name, type: before.type,
      xBefore: before.x, yBefore: before.y,
      xAfter: after.x, yAfter: after.y,
      dxMm: Math.round(dxMm * 10) / 10,
      dyMm: Math.round(dyMm * 10) / 10,
      mag: Math.round(Math.hypot(dxMm, dyMm) * 10) / 10,
    };
  });
}

function get(deltas, id) { return deltas.find(d => d.id === id) ?? null; }

function analyze(deltas, pxPerMm) {
  const SIG = pxPerMm ? 2 : 8;
  const pogonion = get(deltas, 'pogonion');
  const gnathion = get(deltas, 'gnathion');
  const chinMid = get(deltas, 'chin_mid');
  const gonionL = get(deltas, 'gonion_l');
  const gonionR = get(deltas, 'gonion_r');
  const pronasale = get(deltas, 'pronasale');
  const labSup = get(deltas, 'labrale_superius');
  const labInf = get(deltas, 'labrale_inferius');
  const jawL1 = get(deltas, 'jaw_l1');
  const jawR1 = get(deltas, 'jaw_r1');

  const chinAdv = pogonion && pogonion.dxMm > SIG;
  const chinInf = (gnathion && gnathion.dyMm > SIG) || (chinMid && chinMid.dyMm > SIG);
  const chinSup = (gnathion && gnathion.dyMm < -SIG) || (chinMid && chinMid.dyMm < -SIG);
  const mandAdv = (gonionL && gonionL.dxMm > SIG) || (gonionR && gonionR.dxMm > SIG);
  const mandRet = (gonionL && gonionL.dxMm < -SIG) || (gonionR && gonionR.dxMm < -SIG);
  const jawWidened = (jawL1 && jawL1.dxMm < -SIG) || (jawR1 && jawR1.dxMm > SIG);
  const noseModif = pronasale && pronasale.mag > SIG;
  const upperLipUp = labSup && labSup.dyMm < -SIG;
  const lowerLipDn = labInf && labInf.dyMm > SIG;

  const procs = [];
  let classification = 'Facial skeletal assessment';
  let reasoning = '';

  if (mandAdv || chinAdv) { procs.push('Bilateral Sagittal Split Osteotomy (BSSO) — Advancement'); classification = 'Angle Class II — Retrognathic Mandible'; reasoning += 'Anterior movement of mandibular landmarks indicates mandibular deficiency. '; }
  if (mandRet) { procs.push('BSSO — Mandibular Setback'); classification = 'Angle Class III — Prognathic Mandible'; reasoning += 'Posterior repositioning of mandibular landmarks detected. '; }
  if (chinAdv || chinInf || chinSup) { procs.push('Sliding Genioplasty'); reasoning += 'Chin repositioning in multiple planes indicates genioplasty. '; }
  if (jawWidened) { procs.push('SARPE (Surgically Assisted Rapid Palatal Expansion)'); reasoning += 'Lateral jaw widening pattern suggests transverse maxillary deficiency. '; }
  if (upperLipUp) { procs.push('Le Fort I Osteotomy — Superior Impaction'); classification = 'Vertical Maxillary Excess'; reasoning += 'Superior lip movement indicates vertical maxillary excess. '; }
  if (lowerLipDn && !mandAdv) { procs.push('Le Fort I Osteotomy — Inferior Repositioning'); reasoning += 'Inferior lip movement may indicate maxillary vertical deficiency. '; }
  if (noseModif && !mandAdv && !mandRet) { procs.push('Rhinoplasty / Nasal Osteotomy'); reasoning += 'Nasal landmark modifications suggest concurrent rhinoplasty. '; }

  const procedure = procs.length ? procs.join(' + ') : 'No Surgery Required';
  if (!procs.length) { classification = 'No major skeletal discrepancy detected'; reasoning = 'Landmark movements are primarily in soft tissue.'; }
  if (!reasoning.trim()) reasoning = 'Landmark movements indicate skeletal discrepancy requiring surgical correction.';

  const KEY_IDS = ['pogonion', 'gnathion', 'gonion_l', 'gonion_r', 'subnasale', 'labrale_superius', 'labrale_inferius', 'pronasale'];
  const measurements = deltas.filter(d => KEY_IDS.includes(d.id) && d.mag > (pxPerMm ? 1 : 3)).slice(0, 8).map(d => {
    const direction = Math.abs(d.dxMm) >= Math.abs(d.dyMm) ? (d.dxMm > 0 ? 'advance' : 'retract') : (d.dyMm > 0 ? 'inferior' : 'superior');
    return { landmark: d.name, currentMm: null, targetMm: null, deltaMm: d.mag, direction };
  });

  const targetLandmarks = deltas.filter(d => d.mag > (pxPerMm ? 1 : 3)).map(d => ({ id: d.id, x: Math.round(d.xAfter), y: Math.round(d.yAfter) }));
  const movedCount = deltas.filter(d => d.mag > (pxPerMm ? 1 : 3)).length;
  const confidence = movedCount >= 5 ? 'high' : movedCount >= 2 ? 'medium' : 'low';

  return { procedure, classification, reasoning: reasoning.trim(), measurements, targetLandmarks, confidence };
}

app.post('/api/analyze', (req, res) => {
  try {
    const { initialLandmarks, modifiedLandmarks, calibration } = req.body;
    if (!initialLandmarks?.length || !modifiedLandmarks?.length)
      return res.status(400).json({ message: 'initialLandmarks and modifiedLandmarks are required.' });
    const pxPerMm = calibration?.pixelsPerMm ?? null;
    const deltas = buildDeltas(initialLandmarks, modifiedLandmarks, pxPerMm);
    res.json(analyze(deltas, pxPerMm));
  } catch (e) {
    console.error('/api/analyze error:', e);
    res.status(500).json({ message: 'Analysis failed: ' + e.message });
  }
});

// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`WAJH backend running on http://localhost:${PORT}`));
export default app;