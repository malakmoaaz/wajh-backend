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
// Static list for localhost dev, plus a dynamic check that allows any
// *.vercel.app origin — Vercel project URLs and preview-deployment URLs
// change often (this project alone has used wajh-frontend, wajh-web, and
// project-fy7jg as different Vercel domains), so hardcoding one exact
// domain breaks the moment Vercel issues a different one.
const STATIC_ALLOWED_ORIGINS = [
  'http://localhost:5173',
  'http://localhost:3000',
];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true); // non-browser requests (curl, health checks)
    if (STATIC_ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    if (/^https:\/\/[a-z0-9-]+\.vercel\.app$/i.test(origin)) return callback(null, true);
    return callback(new Error(`Not allowed by CORS: ${origin}`));
  },
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

// Patient-facing: the logged-in PATIENT account's own record, matched by the
// email their account was registered with against Patient.email (set by the
// doctor when linking the account in Admin Dashboard / Save This Result).
app.get('/api/patient/me', authenticateToken, async (req, res) => {
  try {
    const patient = await prisma.patient.findFirst({
      where: { email: req.user.email },
      include: {
        cases: {
          orderBy: { createdAt: 'desc' },
          include: { simulations: { orderBy: { createdAt: 'desc' } } }
        }
      }
    });
    if (!patient) {
      return res.status(404).json({ message: 'No patient record is linked to this account yet. Ask your doctor to link it.' });
    }
    res.json(patient);
  } catch (e) { res.status(500).json({ message: e.message }); }
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
const PHI = 1.618033988749895;

// Converts rule-based ideal target positions (from computeCephTargets) into
// the same {id, name, dxMm, dyMm, mag, xBefore, yBefore, xAfter, yAfter}
// shape buildDeltas() produces, but measuring deviation of the CURRENT
// landmark state from the computed ideal — not from the original detection.
// This lets analyze() (unchanged) drive the procedure recommendation off
// "how far is this patient from anatomically ideal proportions right now",
// which is correct both on first load (current === initial, full deviation
// shown) and live as the doctor manually corrects landmarks (deviation
// shrinks toward the target) — the hybrid manual + AI behavior.
function buildIdealDeltas(currentLandmarks, idealTargets, pxPerMm) {
  const curMap = new Map(currentLandmarks.map(l => [l.id, l]));
  return idealTargets.map(t => {
    const cur = curMap.get(t.id);
    if (!cur) return null;
    const dxPx = t.x - cur.x;
    const dyPx = t.y - cur.y;
    const dxMm = pxPerMm ? dxPx / pxPerMm : dxPx;
    const dyMm = pxPerMm ? dyPx / pxPerMm : dyPx;
    return {
      id: t.id, name: cur.name || t.id,
      xBefore: cur.x, yBefore: cur.y, xAfter: t.x, yAfter: t.y,
      dxMm: Math.round(dxMm * 10) / 10,
      dyMm: Math.round(dyMm * 10) / 10,
      mag: Math.round(Math.hypot(dxMm, dyMm) * 10) / 10,
    };
  }).filter(Boolean);
}

function computeGoldenRatio(modifiedLandmarks, pxPerMm) {
  const lmMap = new Map(modifiedLandmarks.map(l => [l.id, l]));
  const scale = pxPerMm || 5.0;
  const dist = (a, b) => {
    const la = lmMap.get(a), lb = lmMap.get(b);
    if (!la || !lb) return null;
    return Math.hypot(la.x - lb.x, la.y - lb.y) / scale;
  };

  const results = {};
  const lfh = dist('subnasale', 'gnathion');
  const ufh = dist('nasion', 'subnasale');

  if (lfh && ufh && ufh > 0) {
    const ratio = lfh / ufh;
    results.face_height_ratio = {
      current: Math.round(ratio * 1000) / 1000,
      ideal: Math.round(PHI * 1000) / 1000,
      deviation_mm: Math.round(Math.abs(ratio - PHI) * ufh * 10) / 10,
      label: 'Lower / Upper Face Height',
      within_norm: Math.abs(ratio - PHI) < 0.15,
    };
  }

  const fw = dist('zygion_l', 'zygion_r');
  const jw = dist('gonion_l', 'gonion_r');
  if (fw && jw && fw > 0) {
    const ratio = jw / fw;
    const ideal = 1 / PHI;
    results.jaw_face_width_ratio = {
      current: Math.round(ratio * 1000) / 1000,
      ideal: Math.round(ideal * 1000) / 1000,
      deviation_mm: Math.round(Math.abs(ratio - ideal) * fw * 10) / 10,
      label: 'Jaw Width / Face Width',
      within_norm: Math.abs(ratio - ideal) < 0.08,
    };
  }

  const devs = Object.values(results).map(v => v.deviation_mm);
  const score = devs.length
    ? Math.max(0, Math.min(100, Math.round(100 - (devs.reduce((a, b) => a + b, 0) / devs.length) * 4)))
    : 100;

  const overallAssessment =
    score >= 85 ? 'Excellent facial harmony' :
    score >= 70 ? 'Good harmony with minor deviations' :
    score >= 50 ? 'Moderate deviations — surgical correction may improve harmony' :
    'Significant deviations from golden ratio';

  return { ratios: results, harmonyScore: score, overallAssessment };
}
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
  // Confidence reflects how clearly the cephalometric assessment supports a
  // specific procedure recommendation, not just how many landmarks moved:
  // - HIGH:   a real procedure was detected AND 3+ landmarks show significant
  //           deviation from ideal (clear clinical indication)
  // - MEDIUM: a procedure was detected with at least 1 significant landmark,
  //           or no procedure but 3+ landmarks deviate (borderline case)
  // - LOW:    no significant deviations, or insufficient landmark data
  const hasProcedure = procs.length > 0;
  const confidence = hasProcedure && movedCount >= 3 ? 'high'
      : hasProcedure && movedCount >= 1 ? 'medium'
      : movedCount >= 3 ? 'medium'
      : 'low';

  return { procedure, classification, reasoning: reasoning.trim(), measurements, targetLandmarks, confidence };
}
// ── CEPHALOMETRIC TARGET COMPUTATION ─────────────────────────────────────────
// Computes patient-specific ideal landmark positions based on published norms:
//   Norm 1 (Ricketts): Lower face height / Upper face height = φ (1.618)
//   Norm 2 (Ricketts): Jaw width / Face width = 1/φ (0.618)
// Soft tissue ratios from Proffit & White, Contemporary Orthodontics:
//   Lower lip follows mandible at 70%, stomion at 50%, upper lip at 30%
function computeCephTargets(initialLandmarks, pxPerMm) {
    const lm     = new Map(initialLandmarks.map(l => [l.id, l]));
    const scale  = pxPerMm || 5.0;
    const targets = [];

    const nasion    = lm.get('nasion');
    const subnasale = lm.get('subnasale');
    const gnathion  = lm.get('gnathion');
    const gonionL   = lm.get('gonion_l');
    const gonionR   = lm.get('gonion_r');
    const zygionL   = lm.get('zygion_l');
    const zygionR   = lm.get('zygion_r');
    const pogonion  = lm.get('pogonion');
    const chinMid   = lm.get('chin_mid');
    const menton    = lm.get('menton');
    const labSup    = lm.get('labrale_superius');
    const labInf    = lm.get('labrale_inferius');
    const stomion   = lm.get('stomion');

    // ── Norm 1: LFH / UFH = φ ────────────────────────────────────────────
    // UFH = nasion → subnasale, LFH = subnasale → gnathion
    // If LFH ≠ UFH × φ, compute where gnathion (and dependent landmarks) should be
    if (nasion && subnasale && gnathion) {
        const ufhPx      = subnasale.y - nasion.y;
        const lfhPx      = gnathion.y  - subnasale.y;
        const idealLfhPx = ufhPx * PHI;
        const deltaY     = idealLfhPx - lfhPx;        // positive = gnathion moves down
        const devMm      = Math.abs(deltaY) / scale;

        if (devMm >= 2) {
            targets.push({ id: 'gnathion', x: Math.round(gnathion.x), y: Math.round(gnathion.y + deltaY) });

            // Hard tissue: pogonion moves 85% of gnathion delta, chin_mid 90%, menton 100%
            if (pogonion) targets.push({ id: 'pogonion', x: Math.round(pogonion.x), y: Math.round(pogonion.y + deltaY * 0.85) });
            if (chinMid)  targets.push({ id: 'chin_mid',  x: Math.round(chinMid.x),  y: Math.round(chinMid.y  + deltaY * 0.90) });
            if (menton)   targets.push({ id: 'menton',    x: Math.round(menton.x),   y: Math.round(menton.y   + deltaY * 1.00) });

            // Soft tissue ratios (Proffit & White)
            if (labInf)  targets.push({ id: 'labrale_inferius', x: Math.round(labInf.x),  y: Math.round(labInf.y  + deltaY * 0.70) });
            if (stomion) targets.push({ id: 'stomion',          x: Math.round(stomion.x), y: Math.round(stomion.y + deltaY * 0.50) });
            if (labSup)  targets.push({ id: 'labrale_superius', x: Math.round(labSup.x),  y: Math.round(labSup.y  + deltaY * 0.30) });
        }
    }

    // ── Norm 2: Jaw width / Face width = 1/φ ─────────────────────────────
    // JW = gonion_l → gonion_r, FW = zygion_l → zygion_r, ideal JW/FW = 0.618
    if (gonionL && gonionR && zygionL && zygionR) {
        const fwPx        = zygionR.x  - zygionL.x;
        const jwPx        = gonionR.x  - gonionL.x;
        const idealJwPx   = fwPx / PHI;
        const midX        = (gonionL.x + gonionR.x) / 2;
        const devMm       = Math.abs(idealJwPx - jwPx) / scale;

        if (devMm >= 1.5) {
            targets.push({ id: 'gonion_l', x: Math.round(midX - idealJwPx / 2), y: Math.round(gonionL.y) });
            targets.push({ id: 'gonion_r', x: Math.round(midX + idealJwPx / 2), y: Math.round(gonionR.y) });
        }
    }

    return targets;
}
app.post('/api/analyze', (req, res) => {
  try {
    const { initialLandmarks, modifiedLandmarks, calibration } = req.body;
    if (!initialLandmarks?.length || !modifiedLandmarks?.length)
      return res.status(400).json({ message: 'initialLandmarks and modifiedLandmarks are required.' });
    const pxPerMm = calibration?.pixelsPerMm ?? null;

    // Rule-based ideal positions, computed once from the patient's own
    // original (undisplaced) anatomy via the φ-ratio Ricketts norms — fixed
    // per patient regardless of any later manual edits.
    const idealTargets = computeCephTargets(initialLandmarks, pxPerMm);

    // Deviation of the CURRENT landmark state from that ideal. On first load
    // (modifiedLandmarks === initialLandmarks) this is the full baseline
    // deviation; as the doctor manually corrects a landmark it shrinks
    // toward zero. This is what actually drives the recommendation.
    const idealDeltas = buildIdealDeltas(modifiedLandmarks, idealTargets, pxPerMm);
    const idealIds = new Set(idealDeltas.map(d => d.id));

    // A few procedure triggers (nasal modification, transverse jaw widening)
    // aren't covered by either φ-ratio norm — there's no computed ideal
    // target for them. For those specific landmarks only, fall back to
    // genuine manual-drag deltas (modified vs initial) so deliberate doctor
    // exploration still surfaces those procedures; they just won't get a
    // fabricated equation-based mm value in the landmark list below.
    const dragDeltas = buildDeltas(initialLandmarks, modifiedLandmarks, pxPerMm)
      .filter(d => !idealIds.has(d.id));

    const result = analyze([...idealDeltas, ...dragDeltas], pxPerMm);
    result.goldenRatio = computeGoldenRatio(modifiedLandmarks, pxPerMm);
    result.targetLandmarks = idealTargets;

    // Per-landmark recommendation list for the UI: real computed mm + a
    // target position to apply, one row per landmark that's clinically
    // significant per the φ-ratio formulas — no static numbers.
    result.recommendedLandmarkMoves = idealDeltas
      .filter(d => d.mag > 0.3)
      .map(d => ({
        id: d.id, name: d.name, deltaMm: d.mag,
        direction: Math.abs(d.dxMm) >= Math.abs(d.dyMm)
          ? (d.dxMm > 0 ? 'advance' : 'retract')
          : (d.dyMm > 0 ? 'inferior' : 'superior'),
        targetX: d.xAfter, targetY: d.yAfter,
      }))
      .sort((a, b) => b.deltaMm - a.deltaMm);

    res.json(result);
  } catch (e) {
    console.error('/api/analyze error:', e);
    res.status(500).json({ message: 'Analysis failed: ' + e.message });
  }
});


// ── START ─────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`WAJH backend running on http://localhost:${PORT}`));
export default app;