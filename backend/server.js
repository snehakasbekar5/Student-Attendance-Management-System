const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = 3000;
const FILE = path.join(__dirname, "students.json");
const USERS_FILE = path.join(__dirname, "users.json");
const SEED_MARKER_FILE = path.join(__dirname, ".demo_seeded.json");
const TOKEN_SECRET = "student-attendance-secret-key-2026-local";

// Middleware
app.use(cors());
app.use(express.json());

// Available classes
const classes = [
    "CSE-(I)SE DS",
    "CSE-(I)SE R&AI",
    "CSE-(R)SE",
    "CSE-(I)TE DS",
    "CSE-(I)TE R&AI",
    "CSE-(R)TE"
];

// Available subjects
const subjects = [
    "Maths",
    "DSA",
    "C",
    "Python",
    "Java",
    "C++"
];

// ==========================================
// SAFE FILE I/O HELPERS
// ==========================================

function readJsonFile(filePath, fallback = []) {
    try {
        if (!fs.existsSync(filePath)) {
            return fallback;
        }
        const raw = fs.readFileSync(filePath, "utf8");
        if (!raw || !raw.trim()) {
            return fallback;
        }
        return JSON.parse(raw);
    } catch (err) {
        console.error(`Error reading JSON file ${filePath}:`, err.message);
        return fallback;
    }
}

function writeJsonFile(filePath, data) {
    const jsonString = JSON.stringify(data, null, 2);
    const tmpPath = `${filePath}.tmp`;
    try {
        fs.writeFileSync(tmpPath, jsonString, "utf8");
        fs.renameSync(tmpPath, filePath);
    } catch (err) {
        // Fallback direct write if rename is locked on Windows
        fs.writeFileSync(filePath, jsonString, "utf8");
        if (fs.existsSync(tmpPath)) {
            try {
                fs.unlinkSync(tmpPath);
            } catch (_) {}
        }
    }
}

// ==========================================
// DATE & CALCULATION HELPERS
// ==========================================

function normalizeDate(dateStr) {
    if (!dateStr || typeof dateStr !== "string") return "";
    const trimmed = dateStr.trim();
    // Already YYYY-MM-DD
    if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
        return trimmed;
    }
    // Convert DD-MM-YYYY to YYYY-MM-DD
    const dmyMatch = trimmed.match(/^(\d{2})-(\d{2})-(\d{4})$/);
    if (dmyMatch) {
        return `${dmyMatch[3]}-${dmyMatch[2]}-${dmyMatch[1]}`;
    }
    return trimmed;
}

function normalizeStatus(status) {
    if (!status || typeof status !== "string") return "";
    const lower = status.trim().toLowerCase();
    if (lower === "present" || lower === "absent") {
        return lower;
    }
    return "";
}

/**
 * Attendance Calculation Policy:
 * Attendance percentage = Present sessions / Total finalized attendance sessions * 100
 * Only finalized records with status 'present' or 'absent' are counted.
 * Unmarked or draft sessions are never counted as finalized attendance.
 */
function calculateAttendanceStats(records) {
    const finalized = (records || []).filter(r => {
        const s = normalizeStatus(r.status);
        return s === "present" || s === "absent";
    });
    const presentCount = finalized.filter(r => normalizeStatus(r.status) === "present").length;
    const absentCount = finalized.filter(r => normalizeStatus(r.status) === "absent").length;
    const totalSessions = presentCount + absentCount;
    const percentage = totalSessions > 0
        ? Number(((presentCount / totalSessions) * 100).toFixed(2))
        : 0;

    return {
        totalSessions,
        presentCount,
        absentCount,
        percentage
    };
}

// ==========================================
// AUTHENTICATION & TOKEN HELPERS
// ==========================================

function createAuthToken(payload) {
    const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const sig = crypto
        .createHmac("sha256", TOKEN_SECRET)
        .update(data)
        .digest("base64url");
    return `${data}.${sig}`;
}

function verifyAuthToken(token) {
    if (!token || typeof token !== "string" || !token.includes(".")) {
        return null;
    }
    const [data, sig] = token.split(".");
    const expectedSig = crypto
        .createHmac("sha256", TOKEN_SECRET)
        .update(data)
        .digest("base64url");
    if (sig !== expectedSig) {
        return null;
    }
    try {
        return JSON.parse(Buffer.from(data, "base64url").toString("utf8"));
    } catch (_) {
        return null;
    }
}

function getCallerIdentity(req) {
    const authHeader = req.headers["authorization"] || "";
    if (authHeader.startsWith("Bearer ")) {
        const token = authHeader.slice(7).trim();
        const verified = verifyAuthToken(token);
        if (verified) {
            return verified;
        }
        return { role: "invalid_token" };
    }
    const headerRole = (req.headers["x-user-role"] || "").toString().trim().toLowerCase();
    const bodyRole = (req.body && req.body.role ? req.body.role : "").toString().trim().toLowerCase();
    const role = headerRole || bodyRole;
    if (role === "student") {
        return {
            role: "student",
            prn: req.headers["x-student-prn"] || (req.body && req.body.studentPrn) || null
        };
    }
    if (role === "faculty") {
        return {
            role: "faculty",
            username: req.headers["x-username"] || "faculty1",
            facultyId: req.headers["x-faculty-id"] || "faculty1"
        };
    }
    return { role: "anonymous" };
}

function requireFacultyPermission(req, res, next) {
    const caller = getCallerIdentity(req);
    if (caller.role === "invalid_token") {
        return res.status(401).json({
            message: "Unauthorized: Invalid authentication token."
        });
    }
    if (caller.role === "student") {
        return res.status(403).json({
            message: "Forbidden: Students are not authorized to modify student or attendance records."
        });
    }
    req.caller = caller;
    next();
}

// ==========================================
// ACTIVE ROSTER: ONLY THE 10 STUDENTS SPECIFIED
// ==========================================

const TARGET_10_STUDENTS_SPEC = [
    // CSE-(I)SE DS: Sneha, Riddhi
    { prn: "1001", name: "Sneha", rollNo: "DS2-01", className: "CSE-(I)SE DS", department: "Computer Science", email: "sneha.1001@college.edu", absentSubjects: ["C"] },
    { prn: "1002", name: "Riddhi", rollNo: "DS2-02", className: "CSE-(I)SE DS", department: "Computer Science", email: "riddhi.1002@college.edu", absentSubjects: [] },

    // CSE-(I)SE R&AI: Siddhi, Shravni
    { prn: "1003", name: "Siddhi", rollNo: "RAI2-01", className: "CSE-(I)SE R&AI", department: "Computer Science", email: "siddhi.1003@college.edu", absentSubjects: ["Maths", "Python"] },
    { prn: "1004", name: "Shravni", rollNo: "RAI2-02", className: "CSE-(I)SE R&AI", department: "Computer Science", email: "shravni.1004@college.edu", absentSubjects: ["Java"] },

    // CSE-(R)SE: Umme Hanni, Vaishnavi
    { prn: "1005", name: "Umme Hanni", rollNo: "RSE-01", className: "CSE-(R)SE", department: "Computer Science", email: "umme.hanni.1005@college.edu", absentSubjects: [] },
    { prn: "1006", name: "Vaishnavi", rollNo: "RSE-02", className: "CSE-(R)SE", department: "Computer Science", email: "vaishnavi.1006@college.edu", absentSubjects: ["DSA", "C++"] },

    // CSE-(I)TE DS: Anuja, Rohan
    { prn: "1007", name: "Anuja", rollNo: "DS3-01", className: "CSE-(I)TE DS", department: "Computer Science", email: "anuja.1007@college.edu", absentSubjects: ["DSA"] },
    { prn: "1008", name: "Rohan", rollNo: "DS3-02", className: "CSE-(I)TE DS", department: "Computer Science", email: "rohan.1008@college.edu", absentSubjects: [] },

    // CSE-(I)TE R&AI: Mohit
    { prn: "1009", name: "Mohit", rollNo: "RAI3-01", className: "CSE-(I)TE R&AI", department: "Computer Science", email: "mohit.1009@college.edu", absentSubjects: ["C", "Java"] },

    // CSE-(R)TE: Parth
    { prn: "1010", name: "Parth", rollNo: "RTE-01", className: "CSE-(R)TE", department: "Computer Science", email: "parth.1010@college.edu", absentSubjects: ["Python"] }
];

// Historical sessions for the 10 students across 6 subjects on previous dates
// Notice: NO records on 2026-10-13 (Today) - Today starts completely Unmarked
const HISTORICAL_SESSIONS = [
    { date: "2026-10-05", subject: "Maths" },
    { date: "2026-10-06", subject: "DSA" },
    { date: "2026-10-07", subject: "C" },
    { date: "2026-10-08", subject: "Python" },
    { date: "2026-10-09", subject: "Java" },
    { date: "2026-10-12", subject: "C++" }
];

function seedDemoDataIfNeeded() {
    let students = readJsonFile(FILE, []);
    let users = readJsonFile(USERS_FILE, []);
    const marker = readJsonFile(SEED_MARKER_FILE, null);

    const validTargetPrns = new Set(TARGET_10_STUDENTS_SPEC.map(s => s.prn));

    // 1. Check if roster needs updating to the 10-student specification
    const hasOldDemoStudents = students.some(s => !validTargetPrns.has(s.prn) && s.isDemo);
    const missingTargetStudents = TARGET_10_STUDENTS_SPEC.some(spec => !students.some(s => s.prn === spec.prn));
    const isMarkerUpToDate = marker && marker.rosterVersion === "10_students_v1";
    const hasSnehaUser = users.some(u => u.username === "sneha" && u.password === "sneha123");

    let studentsModified = false;
    let usersModified = false;

    if (!isMarkerUpToDate || hasOldDemoStudents || missingTargetStudents || !hasSnehaUser) {
        // Remove old demo students completely
        students = students.filter(s => validTargetPrns.has(s.prn) || !s.isDemo);

        // Ensure each of the 10 target students exists with correct class & historical attendance
        TARGET_10_STUDENTS_SPEC.forEach(spec => {
            let student = students.find(s => s.prn === spec.prn);
            if (!student) {
                student = {
                    prn: spec.prn,
                    studentId: spec.prn,
                    name: spec.name,
                    rollNo: spec.rollNo,
                    className: spec.className,
                    department: spec.department,
                    email: spec.email,
                    isDemo: true,
                    attendanceRecords: []
                };
                students.push(student);
                studentsModified = true;
            } else {
                student.name = spec.name;
                student.rollNo = spec.rollNo;
                student.className = spec.className;
                student.department = spec.department;
                student.email = spec.email;
                student.isDemo = true;
                studentsModified = true;
            }

            // Ensure historical attendance is populated and free of old dates/records
            HISTORICAL_SESSIONS.forEach(sess => {
                const existingRec = (student.attendanceRecords || []).find(
                    r => normalizeDate(r.date) === sess.date && r.subject === sess.subject
                );
                const status = spec.absentSubjects.includes(sess.subject) ? "absent" : "present";
                if (!existingRec) {
                    if (!Array.isArray(student.attendanceRecords)) {
                        student.attendanceRecords = [];
                    }
                    student.attendanceRecords.push({
                        studentId: student.prn,
                        prn: student.prn,
                        date: sess.date,
                        className: student.className,
                        subject: sess.subject,
                        status: status,
                        facultyId: "faculty1",
                        isDemo: true
                    });
                    studentsModified = true;
                }
            });

            // Ensure today's date (2026-10-13) has NO records initially (starts Unmarked)
            student.attendanceRecords = (student.attendanceRecords || []).filter(
                r => normalizeDate(r.date) !== "2026-10-13"
            );
        });

        // 2. Synchronize users.json:
        // Preserve all faculty accounts (faculty1, faculty2, etc.) and any non-student accounts
        const facultyAndAdmins = users.filter(u => u.role !== "student");

        // Build student accounts including 'sneha' (password 'sneha123') and 'student1'..'student10'
        const targetStudentUsers = [
            {
                username: "sneha",
                password: "sneha123",
                role: "student",
                prn: "1001",
                name: "Sneha",
                isDemo: true
            },
            ...TARGET_10_STUDENTS_SPEC.map((spec, index) => ({
                username: `student${index + 1}`,
                password: "student123",
                role: "student",
                prn: spec.prn,
                name: spec.name,
                isDemo: true
            }))
        ];

        users = [...facultyAndAdmins, ...targetStudentUsers];
        usersModified = true;

        // Write marker file to lock in 10-student version
        writeJsonFile(SEED_MARKER_FILE, {
            rosterVersion: "10_students_v1",
            updatedAt: new Date().toISOString(),
            studentCount: 10,
            hasSnehaLogin: true,
            students: TARGET_10_STUDENTS_SPEC.map(s => `${s.name} (${s.prn}) - ${s.className}`)
        });
    }

    if (studentsModified) {
        writeJsonFile(FILE, students);
    }
    if (usersModified) {
        writeJsonFile(USERS_FILE, users);
    }
}

// Run idempotent seed on startup
seedDemoDataIfNeeded();

// ==========================================
// ROUTES
// ==========================================

// Home page
app.get("/", (req, res) => {
    res.send("Student Attendance Management System Backend is Running!");
});

// Get available classes
app.get("/classes", (req, res) => {
    res.json(classes);
});

// Get available subjects
app.get("/subjects", (req, res) => {
    res.json(subjects);
});

// LOGIN
app.post("/login", (req, res) => {
    const username = (req.body && req.body.username ? String(req.body.username) : "").trim();
    const password = req.body && req.body.password ? String(req.body.password) : "";

    if (!username || !password) {
        return res.status(400).json({
            message: "Username and password are required"
        });
    }

    const users = readJsonFile(USERS_FILE, []);
    const students = readJsonFile(FILE, []);

    let user = users.find(
        u => u.username.toLowerCase() === username.toLowerCase() && u.password === password
    );

    // Also allow any registered student to log in with their Student ID / PRN or First Name
    if (!user) {
        const matchedStudent = students.find(
            s => s.prn.toLowerCase() === username.toLowerCase() ||
                 (s.studentId && s.studentId.toLowerCase() === username.toLowerCase()) ||
                 s.name.toLowerCase() === username.toLowerCase()
        );
        if (matchedStudent) {
            // If Sneha logging in with PRN 1001, allow both sneha123 and student123
            if (matchedStudent.prn === "1001" && (password === "sneha123" || password === "student123")) {
                user = {
                    username: "sneha",
                    role: "student",
                    prn: "1001",
                    name: "Sneha"
                };
            } else if (password === "student123") {
                user = {
                    username: matchedStudent.prn,
                    role: "student",
                    prn: matchedStudent.prn,
                    name: matchedStudent.name
                };
            }
        }
    }

    if (!user) {
        return res.status(401).json({
            message: "Invalid username or password"
        });
    }

    // Resolve student details if student login
    let studentInfo = null;
    if (user.role === "student" && user.prn) {
        studentInfo = students.find(s => s.prn === user.prn) || null;
    }

    const tokenPayload = {
        username: user.username,
        role: user.role,
        prn: user.prn || null,
        facultyId: user.role === "faculty" ? (user.facultyId || user.username) : null
    };
    const token = createAuthToken(tokenPayload);

    // Passwords are never included in the API response
    res.json({
        message: "Login successful",
        role: user.role,
        username: user.username,
        prn: user.prn || null,
        studentId: user.prn || null,
        name: studentInfo ? studentInfo.name : (user.name || (user.role === "faculty" ? "Prof. Rajesh Kulkarni" : user.username)),
        className: studentInfo ? studentInfo.className : null,
        facultyId: user.role === "faculty" ? (user.facultyId || user.username) : null,
        token
    });
});

// Get all students (supports optional ?className=... & ?search=...)
app.get("/students", (req, res) => {
    const caller = getCallerIdentity(req);
    const students = readJsonFile(FILE, []);
    const { className, search } = req.query;

    let result = students.map(s => ({
        ...s,
        studentId: s.studentId || s.prn,
        rollNo: s.rollNo || `R-${s.prn}`,
        department: s.department || "Computer Science",
        email: s.email || ""
    }));

    // If caller is authenticated as a student, restrict listing to their own profile only
    if (caller.role === "student" && caller.prn) {
        result = result.filter(s => s.prn === caller.prn);
    }

    if (className && className.trim() !== "") {
        result = result.filter(s => s.className === className.trim());
    }

    if (search && search.trim() !== "") {
        const q = search.trim().toLowerCase();
        result = result.filter(s =>
            (s.name && s.name.toLowerCase().includes(q)) ||
            (s.prn && s.prn.toLowerCase().includes(q)) ||
            (s.studentId && s.studentId.toLowerCase().includes(q)) ||
            (s.rollNo && s.rollNo.toLowerCase().includes(q)) ||
            (s.email && s.email.toLowerCase().includes(q))
        );
    }

    res.json(result);
});

// Get single student by PRN / Student ID
app.get("/students/:prn", (req, res) => {
    const prn = String(req.params.prn || "").trim();
    const caller = getCallerIdentity(req);

    // Prevent student from accessing another student's profile
    if (caller.role === "student" && caller.prn && caller.prn !== prn) {
        return res.status(403).json({
            message: "Forbidden: You are only authorized to view your own student profile."
        });
    }

    const students = readJsonFile(FILE, []);
    const student = students.find(
        s => s.prn === prn || s.studentId === prn
    );

    if (!student) {
        return res.status(404).json({
            message: "Student not found"
        });
    }

    const stats = calculateAttendanceStats(student.attendanceRecords || []);

    res.json({
        ...student,
        studentId: student.studentId || student.prn,
        rollNo: student.rollNo || `R-${student.prn}`,
        stats
    });
});

// Add a student
app.post("/students", requireFacultyPermission, (req, res) => {
    const students = readJsonFile(FILE, []);

    const rawPrn = req.body.prn !== undefined ? req.body.prn : req.body.studentId;
    const prn = String(rawPrn || "").trim();
    const name = String(req.body.name || "").trim();
    const rollNo = String(req.body.rollNo || "").trim();
    const className = String(req.body.className || "").trim();
    const department = String(req.body.department || "Computer Science").trim() || "Computer Science";
    const email = String(req.body.email || "").trim();

    // Validate required fields
    if (!prn) {
        return res.status(400).json({
            message: "Student ID / PRN is required"
        });
    }
    if (!/^[A-Za-z0-9-]{2,20}$/.test(prn)) {
        return res.status(400).json({
            message: "Student ID / PRN must be 2 to 20 alphanumeric characters (e.g., 1011)"
        });
    }
    if (!name || name.length < 2) {
        return res.status(400).json({
            message: "Student full name is required (at least 2 characters)"
        });
    }
    if (!rollNo) {
        return res.status(400).json({
            message: "Roll number is required"
        });
    }
    if (!className || !classes.includes(className)) {
        return res.status(400).json({
            message: "Please select a valid class from the available classes"
        });
    }
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
            message: "Please enter a valid email address"
        });
    }

    // Check duplicate PRN / Student ID globally
    const duplicatePrn = students.find(
        s => s.prn.toLowerCase() === prn.toLowerCase() ||
             (s.studentId && s.studentId.toLowerCase() === prn.toLowerCase())
    );
    if (duplicatePrn) {
        return res.status(409).json({
            message: `Student ID / PRN '${prn}' already exists`
        });
    }

    // Check duplicate Roll Number within the same class
    const duplicateRoll = students.find(
        s => s.className === className &&
             s.rollNo &&
             s.rollNo.toLowerCase() === rollNo.toLowerCase()
    );
    if (duplicateRoll) {
        return res.status(409).json({
            message: `Roll number '${rollNo}' already exists in class '${className}'`
        });
    }

    const newStudent = {
        name,
        prn,
        studentId: prn,
        rollNo,
        className,
        department,
        email: email || `${name.toLowerCase().replace(/\s+/g, ".")}.${prn}@college.edu`,
        attendanceRecords: []
    };

    students.push(newStudent);
    writeJsonFile(FILE, students);

    res.status(201).json({
        message: "Student added successfully",
        student: newStudent
    });
});

// Update a student using PRN
app.put("/students/:prn", requireFacultyPermission, (req, res) => {
    const targetPrn = String(req.params.prn || "").trim();
    const students = readJsonFile(FILE, []);

    const studentIndex = students.findIndex(
        s => s.prn === targetPrn || s.studentId === targetPrn
    );

    if (studentIndex === -1) {
        return res.status(404).json({
            message: "Student not found"
        });
    }

    const existingStudent = students[studentIndex];
    const rawNewPrn = req.body.prn !== undefined ? req.body.prn : (req.body.studentId !== undefined ? req.body.studentId : existingStudent.prn);
    const newPrn = String(rawNewPrn || "").trim();
    const name = String(req.body.name !== undefined ? req.body.name : existingStudent.name).trim();
    const rollNo = String(req.body.rollNo !== undefined ? req.body.rollNo : (existingStudent.rollNo || "")).trim();
    const className = String(req.body.className !== undefined ? req.body.className : existingStudent.className).trim();
    const department = String(req.body.department !== undefined ? req.body.department : (existingStudent.department || "Computer Science")).trim() || "Computer Science";
    const email = String(req.body.email !== undefined ? req.body.email : (existingStudent.email || "")).trim();

    if (!newPrn || !/^[A-Za-z0-9-]{2,20}$/.test(newPrn)) {
        return res.status(400).json({
            message: "Valid Student ID / PRN is required (2 to 20 alphanumeric characters)"
        });
    }
    if (!name || name.length < 2) {
        return res.status(400).json({
            message: "Student full name is required (at least 2 characters)"
        });
    }
    if (!rollNo) {
        return res.status(400).json({
            message: "Roll number is required"
        });
    }
    if (!className || !classes.includes(className)) {
        return res.status(400).json({
            message: "Please select a valid class"
        });
    }
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
            message: "Please enter a valid email address"
        });
    }

    // Check duplicate PRN if changed
    const duplicatePrn = students.find(
        (s, idx) => idx !== studentIndex && (
            s.prn.toLowerCase() === newPrn.toLowerCase() ||
            (s.studentId && s.studentId.toLowerCase() === newPrn.toLowerCase())
        )
    );
    if (duplicatePrn) {
        return res.status(409).json({
            message: `Student ID / PRN '${newPrn}' already exists`
        });
    }

    // Check duplicate Roll Number within target class
    const duplicateRoll = students.find(
        (s, idx) => idx !== studentIndex &&
                    s.className === className &&
                    s.rollNo &&
                    s.rollNo.toLowerCase() === rollNo.toLowerCase()
    );
    if (duplicateRoll) {
        return res.status(409).json({
            message: `Roll number '${rollNo}' already exists in class '${className}'`
        });
    }

    // Keep attendance records consistent if PRN or className changed
    const updatedRecords = (existingStudent.attendanceRecords || []).map(rec => ({
        ...rec,
        studentId: newPrn,
        prn: newPrn,
        className: className
    }));

    const updatedStudent = {
        ...existingStudent,
        name,
        prn: newPrn,
        studentId: newPrn,
        rollNo,
        className,
        department,
        email,
        attendanceRecords: updatedRecords
    };

    students[studentIndex] = updatedStudent;
    writeJsonFile(FILE, students);

    // If PRN changed, keep users.json mapping consistent
    if (existingStudent.prn !== newPrn) {
        const users = readJsonFile(USERS_FILE, []);
        let usersChanged = false;
        users.forEach(u => {
            if (u.prn === existingStudent.prn) {
                u.prn = newPrn;
                usersChanged = true;
            }
        });
        if (usersChanged) {
            writeJsonFile(USERS_FILE, users);
        }
    }

    res.json({
        message: "Student updated successfully",
        student: updatedStudent
    });
});

// Delete student using PRN
app.delete("/students/:prn", requireFacultyPermission, (req, res) => {
    let students = readJsonFile(FILE, []);
    const prn = String(req.params.prn || "").trim();

    const studentExists = students.some(
        student => student.prn === prn || student.studentId === prn
    );

    if (!studentExists) {
        return res.status(404).json({
            message: "Student not found"
        });
    }

    students = students.filter(
        student => student.prn !== prn && student.studentId !== prn
    );

    writeJsonFile(FILE, students);

    res.json({
        message: "Student deleted successfully"
    });
});

// ==========================================
// ATTENDANCE ENDPOINTS
// ==========================================

// Query attendance session status or history
app.get("/attendance", (req, res) => {
    const students = readJsonFile(FILE, []);
    const className = String(req.query.className || "").trim();
    const subject = String(req.query.subject || "").trim();
    const date = normalizeDate(req.query.date || "");

    const classStudents = className
        ? students.filter(s => s.className === className)
        : students;

    // Check if finalized attendance already exists for (className, subject, date)
    let alreadySubmitted = false;
    const studentRows = classStudents.map(student => {
        const records = student.attendanceRecords || [];
        const match = records.find(
            r => normalizeDate(r.date) === date && r.subject === subject
        );
        const status = match ? normalizeStatus(match.status) : "";
        if (status === "present" || status === "absent") {
            alreadySubmitted = true;
        }
        return {
            prn: student.prn,
            studentId: student.studentId || student.prn,
            rollNo: student.rollNo || `R-${student.prn}`,
            name: student.name,
            className: student.className,
            status: status || "unmarked",
            facultyId: match ? (match.facultyId || "faculty1") : null
        };
    });

    const presentCount = studentRows.filter(r => r.status === "present").length;
    const absentCount = studentRows.filter(r => r.status === "absent").length;
    const unmarkedCount = studentRows.filter(r => r.status === "unmarked").length;

    res.json({
        className,
        subject,
        date,
        alreadySubmitted,
        totalStudents: studentRows.length,
        presentCount,
        absentCount,
        unmarkedCount,
        students: studentRows
    });
});

function handleSaveOrUpdateAttendance(req, res, isExplicitUpdate = false) {
    const students = readJsonFile(FILE, []);
    const rawDate = req.body.date;
    const date = normalizeDate(rawDate);
    const className = String(req.body.className || "").trim();
    const subject = String(req.body.subject || "").trim();
    const records = req.body.records;
    const allowUpdate = Boolean(isExplicitUpdate || req.body.allowUpdate === true);
    const facultyId = String(
        req.body.facultyId ||
        (req.caller && req.caller.facultyId) ||
        "faculty1"
    ).trim();

    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
        return res.status(400).json({
            message: "A valid attendance date (YYYY-MM-DD) is required"
        });
    }
    if (!className || !classes.includes(className)) {
        return res.status(400).json({
            message: "Please select a valid class"
        });
    }
    if (!subject || !subjects.includes(subject)) {
        return res.status(400).json({
            message: "Please select a valid subject"
        });
    }
    if (!Array.isArray(records) || records.length === 0) {
        return res.status(400).json({
            message: "Attendance records array is required and cannot be empty"
        });
    }

    const classStudents = students.filter(s => s.className === className);
    if (classStudents.length === 0) {
        return res.status(400).json({
            message: `No students registered in class '${className}'`
        });
    }

    // Check if attendance was already submitted for this class, subject, and date
    const sessionAlreadyExists = classStudents.some(student =>
        (student.attendanceRecords || []).some(
            att => normalizeDate(att.date) === date &&
                   att.subject === subject &&
                   (normalizeStatus(att.status) === "present" || normalizeStatus(att.status) === "absent")
        )
    );

    if (sessionAlreadyExists && !allowUpdate) {
        return res.status(409).json({
            message: `Attendance for ${className} (${subject}) on ${date} has already been submitted. Please use 'Edit Saved Attendance' to update existing records.`,
            alreadySubmitted: true
        });
    }

    // Validate that every student in the class has an explicit 'present' or 'absent' status
    const recordMap = new Map();
    for (const rec of records) {
        const recId = String(rec.prn || rec.studentId || "").trim();
        const normStatus = normalizeStatus(rec.status);
        if (!recId || !normStatus) {
            return res.status(400).json({
                message: "Every student must be explicitly marked as 'present' or 'absent' before submission."
            });
        }
        recordMap.set(recId, normStatus);
    }

    const unmarkedStudents = classStudents.filter(s => !recordMap.has(s.prn));
    if (unmarkedStudents.length > 0) {
        return res.status(400).json({
            message: `Please mark attendance for all students in ${className}. (${unmarkedStudents.length} student(s) unmarked)`
        });
    }

    let presentCount = 0;
    let absentCount = 0;

    classStudents.forEach(student => {
        const status = recordMap.get(student.prn);
        if (status === "present") presentCount++;
        if (status === "absent") absentCount++;

        if (!Array.isArray(student.attendanceRecords)) {
            student.attendanceRecords = [];
        }

        // Deduplicate any existing record for this (date, subject)
        const existingIdx = student.attendanceRecords.findIndex(
            att => normalizeDate(att.date) === date && att.subject === subject
        );

        const recordEntry = {
            studentId: student.prn,
            prn: student.prn,
            date,
            className,
            subject,
            status,
            facultyId,
            updatedAt: new Date().toISOString()
        };

        if (existingIdx !== -1) {
            student.attendanceRecords[existingIdx] = recordEntry;
        } else {
            student.attendanceRecords.push(recordEntry);
        }
    });

    writeJsonFile(FILE, students);

    res.json({
        message: sessionAlreadyExists
            ? "Attendance updated successfully!"
            : "Attendance saved successfully!",
        updated: sessionAlreadyExists,
        summary: {
            date,
            className,
            subject,
            totalStudents: classStudents.length,
            presentCount,
            absentCount
        }
    });
}

// Save new attendance session
app.post("/attendance", requireFacultyPermission, (req, res) => {
    handleSaveOrUpdateAttendance(req, res, false);
});

// Update existing attendance session
app.put("/attendance", requireFacultyPermission, (req, res) => {
    handleSaveOrUpdateAttendance(req, res, true);
});

// ==========================================
// REPORTS & DASHBOARD ENDPOINTS
// ==========================================

// Faculty-wide reports endpoint (Student access blocked)
app.get("/reports", (req, res) => {
    const caller = getCallerIdentity(req);
    if (caller.role === "student") {
        return res.status(403).json({
            message: "Forbidden: Students are not authorized to access faculty attendance reports."
        });
    }

    const students = readJsonFile(FILE, []);
    const className = String(req.query.className || "").trim();
    const subject = String(req.query.subject || "").trim();
    const startDate = normalizeDate(req.query.startDate || "");
    const endDate = normalizeDate(req.query.endDate || "");
    const threshold = req.query.threshold !== undefined ? Number(req.query.threshold) : 75;

    const filteredStudents = (className && className !== "ALL")
        ? students.filter(s => s.className === className)
        : students;

    const sessionKeys = new Set();
    let totalPresent = 0;
    let totalAbsent = 0;
    const historyRecords = [];

    const studentSummaries = filteredStudents.map(student => {
        const records = (student.attendanceRecords || []).filter(rec => {
            const normDate = normalizeDate(rec.date);
            const normStat = normalizeStatus(rec.status);
            if (normStat !== "present" && normStat !== "absent") return false;
            if (subject && subject !== "ALL" && rec.subject !== subject) return false;
            if (startDate && normDate < startDate) return false;
            if (endDate && normDate > endDate) return false;
            return true;
        });

        records.forEach(rec => {
            const normDate = normalizeDate(rec.date);
            const normStat = normalizeStatus(rec.status);
            sessionKeys.add(`${student.className}|${rec.subject}|${normDate}`);
            if (normStat === "present") totalPresent++;
            if (normStat === "absent") totalAbsent++;

            historyRecords.push({
                date: normDate,
                className: student.className,
                subject: rec.subject,
                prn: student.prn,
                studentId: student.studentId || student.prn,
                rollNo: student.rollNo || `R-${student.prn}`,
                studentName: student.name,
                status: normStat,
                facultyId: rec.facultyId || "faculty1"
            });
        });

        const stats = calculateAttendanceStats(records);
        return {
            prn: student.prn,
            studentId: student.studentId || student.prn,
            rollNo: student.rollNo || `R-${student.prn}`,
            name: student.name,
            className: student.className,
            department: student.department || "Computer Science",
            totalSessions: stats.totalSessions,
            presentCount: stats.presentCount,
            absentCount: stats.absentCount,
            percentage: stats.percentage,
            isLowAttendance: stats.totalSessions > 0 && stats.percentage < threshold
        };
    });

    historyRecords.sort((a, b) => {
        if (a.date !== b.date) return b.date.localeCompare(a.date);
        if (a.className !== b.className) return a.className.localeCompare(b.className);
        return (a.rollNo || "").localeCompare(b.rollNo || "");
    });

    const totalFinalizedRecords = totalPresent + totalAbsent;
    const overallPercentage = totalFinalizedRecords > 0
        ? Number(((totalPresent / totalFinalizedRecords) * 100).toFixed(2))
        : 0;

    const lowAttendanceStudents = studentSummaries
        .filter(s => s.isLowAttendance)
        .sort((a, b) => a.percentage - b.percentage);

    res.json({
        filters: { className, subject, startDate, endDate, threshold },
        summary: {
            totalStudents: filteredStudents.length,
            totalDistinctSessions: sessionKeys.size,
            totalFinalizedRecords,
            presentCount: totalPresent,
            absentCount: totalAbsent,
            attendancePercentage: overallPercentage
        },
        studentSummaries,
        lowAttendanceStudents,
        historyRecords
    });
});

// Faculty dashboard metrics (Student access blocked)
app.get("/dashboard/faculty", (req, res) => {
    const caller = getCallerIdentity(req);
    if (caller.role === "student") {
        return res.status(403).json({
            message: "Forbidden: Students are not authorized to access the faculty dashboard."
        });
    }

    const students = readJsonFile(FILE, []);
    const sessionKeys = new Set();
    let totalPresent = 0;
    let totalAbsent = 0;
    let lowAttendanceCount = 0;

    students.forEach(s => {
        const stats = calculateAttendanceStats(s.attendanceRecords || []);
        if (stats.totalSessions > 0 && stats.percentage < 75) {
            lowAttendanceCount++;
        }
        (s.attendanceRecords || []).forEach(r => {
            const st = normalizeStatus(r.status);
            if (st === "present" || st === "absent") {
                sessionKeys.add(`${s.className}|${r.subject}|${normalizeDate(r.date)}`);
                if (st === "present") totalPresent++;
                if (st === "absent") totalAbsent++;
            }
        });
    });

    const totalRecords = totalPresent + totalAbsent;
    const overallAttendancePercentage = totalRecords > 0
        ? Number(((totalPresent / totalRecords) * 100).toFixed(2))
        : 0;

    const classBreakdown = classes.map(cls => {
        const clsStudents = students.filter(s => s.className === cls);
        let clsPresent = 0;
        let clsAbsent = 0;
        clsStudents.forEach(s => {
            const st = calculateAttendanceStats(s.attendanceRecords || []);
            clsPresent += st.presentCount;
            clsAbsent += st.absentCount;
        });
        const clsTotal = clsPresent + clsAbsent;
        return {
            className: cls,
            studentCount: clsStudents.length,
            presentCount: clsPresent,
            absentCount: clsAbsent,
            attendancePercentage: clsTotal > 0 ? Number(((clsPresent / clsTotal) * 100).toFixed(2)) : 0
        };
    });

    res.json({
        totalStudents: students.length,
        totalClasses: classes.length,
        totalSubjects: subjects.length,
        totalSessionsConducted: sessionKeys.size,
        presentCount: totalPresent,
        absentCount: totalAbsent,
        overallAttendancePercentage,
        lowAttendanceCount,
        classBreakdown
    });
});

// Student dashboard endpoint (Enforces caller authentication & PRN match)
app.get("/dashboard/student/:prn", (req, res) => {
    const targetPrn = String(req.params.prn || "").trim();
    const threshold = req.query.threshold !== undefined ? Number(req.query.threshold) : 75;

    const caller = getCallerIdentity(req);

    if (caller.role === "invalid_token") {
        return res.status(401).json({
            message: "Unauthorized: Invalid authentication token."
        });
    }

    if (caller.role === "anonymous") {
        return res.status(401).json({
            message: "Unauthorized: Please log in to view student dashboard."
        });
    }

    // A student can ONLY view their own dashboard
    if (caller.role === "student" && caller.prn && caller.prn !== targetPrn) {
        return res.status(403).json({
            message: "Forbidden: You are only authorized to view your own attendance dashboard."
        });
    }

    const students = readJsonFile(FILE, []);
    const student = students.find(
        s => s.prn === targetPrn || s.studentId === targetPrn
    );

    if (!student) {
        return res.status(404).json({
            message: "Student not found"
        });
    }

    const overallStats = calculateAttendanceStats(student.attendanceRecords || []);

    const subjectWise = subjects.map(subj => {
        const subjRecords = (student.attendanceRecords || []).filter(r => r.subject === subj);
        const st = calculateAttendanceStats(subjRecords);
        return {
            subject: subj,
            totalSessions: st.totalSessions,
            presentCount: st.presentCount,
            absentCount: st.absentCount,
            percentage: st.percentage,
            belowThreshold: st.totalSessions > 0 && st.percentage < threshold
        };
    });

    const recentHistory = (student.attendanceRecords || [])
        .filter(r => {
            const s = normalizeStatus(r.status);
            return s === "present" || s === "absent";
        })
        .map(r => ({
            date: normalizeDate(r.date),
            subject: r.subject,
            status: normalizeStatus(r.status),
            className: r.className || student.className,
            facultyId: r.facultyId || "faculty1"
        }))
        .sort((a, b) => b.date.localeCompare(a.date));

    res.json({
        student: {
            name: student.name,
            prn: student.prn,
            studentId: student.studentId || student.prn,
            rollNo: student.rollNo || `R-${student.prn}`,
            className: student.className,
            department: student.department || "Computer Science",
            email: student.email || ""
        },
        threshold,
        overall: {
            ...overallStats,
            belowThreshold: overallStats.totalSessions > 0 && overallStats.percentage < threshold
        },
        subjectWise,
        recentHistory
    });
});

// Student personal report endpoint (strictly for authenticated student's own records)
app.get("/student/my-report", (req, res) => {
    const caller = getCallerIdentity(req);

    if (caller.role === "invalid_token" || caller.role === "anonymous") {
        return res.status(401).json({
            message: "Unauthorized: Please log in as a student."
        });
    }

    if (caller.role !== "student" || !caller.prn) {
        return res.status(403).json({
            message: "Forbidden: Student authentication required."
        });
    }

    const threshold = req.query.threshold !== undefined ? Number(req.query.threshold) : 75;
    const students = readJsonFile(FILE, []);
    const student = students.find(s => s.prn === caller.prn);

    if (!student) {
        return res.status(404).json({
            message: "Student record not found."
        });
    }

    const overallStats = calculateAttendanceStats(student.attendanceRecords || []);

    const subjectWise = subjects.map(subj => {
        const subjRecords = (student.attendanceRecords || []).filter(r => r.subject === subj);
        const st = calculateAttendanceStats(subjRecords);
        return {
            subject: subj,
            totalSessions: st.totalSessions,
            presentCount: st.presentCount,
            absentCount: st.absentCount,
            percentage: st.percentage,
            belowThreshold: st.totalSessions > 0 && st.percentage < threshold
        };
    });

    const historicalRecords = (student.attendanceRecords || [])
        .filter(r => {
            const s = normalizeStatus(r.status);
            return s === "present" || s === "absent";
        })
        .map(r => ({
            date: normalizeDate(r.date),
            subject: r.subject,
            status: normalizeStatus(r.status),
            className: r.className || student.className,
            facultyId: r.facultyId || "faculty1"
        }))
        .sort((a, b) => b.date.localeCompare(a.date));

    res.json({
        student: {
            name: student.name,
            prn: student.prn,
            studentId: student.prn,
            rollNo: student.rollNo || `R-${student.prn}`,
            className: student.className,
            department: student.department || "Computer Science",
            email: student.email || ""
        },
        threshold,
        summary: {
            ...overallStats,
            belowThreshold: overallStats.totalSessions > 0 && overallStats.percentage < threshold
        },
        subjectWise,
        historicalRecords
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});