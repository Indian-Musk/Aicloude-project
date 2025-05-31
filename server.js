const express = require('express');
const session = require('express-session');
const admin = require('firebase-admin');
const Stripe = require('stripe');
const path = require('path');
const bodyParser = require('body-parser');
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });
const sgMail = require('@sendgrid/mail');
const otpGenerator = require('generate-password');
require('dotenv').config();
// Initialize SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Firebase Service Account Configuration
const serviceAccount = {
  type: process.env.FIREBASE_TYPE,
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: process.env.FIREBASE_AUTH_URI,
  token_uri: process.env.FIREBASE_TOKEN_URI,
  auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
  client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
  universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN
};


// Validate Service Account
const requiredServiceAccountFields = [
  'type', 'project_id', 'private_key_id', 'private_key',
  'client_email', 'client_id', 'auth_uri', 'token_uri'
];

requiredServiceAccountFields.forEach(field => {
  if (!serviceAccount[field]) {
    console.error(`🚨 Missing required service account field: ${field}`);
    process.exit(1);
  }
});

// Initialize Firebase
const databaseURL = process.env.FIREBASE_DATABASE_URL || 
  `https://${serviceAccount.project_id}.firebaseio.com`;

const firebaseApp = admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: databaseURL,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET
});

// Add this after initializing Firebase
const auth = admin.auth();
const db = admin.firestore();
const storage = admin.storage();
const bucket = storage.bucket();
db.settings({ ignoreUndefinedProperties: true });

// Initialize Stripe
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
// Express Configuration
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'default-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));

// User Middleware
app.use((req, res, next) => {
  if(req.session.uid) {
    req.userRef = db.collection('users').doc(req.session.uid);
  }
  next();
});

// Add this middleware to verify authentication
const verifyAuth = (req, res, next) => {
  if (!req.session.uid) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
};

// ======================
//      Endpoints
// ======================

// Health Check
app.get('/health', (req, res) => {
  res.json({
    status: 'OK',
    firebase: {
      projectId: serviceAccount.project_id,
      database: firebaseApp.options.databaseURL,
      serviceAccount: serviceAccount.client_email
    },
    stripe: !!process.env.STRIPE_SECRET_KEY,
    session: !!process.env.SESSION_SECRET
  });
});

// User Registration
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Email validation
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Create Firebase user
    const user = await auth.createUser({
      email,
      password,
      emailVerified: false
    });

    // Generate OTP
    const otp = otpGenerator.generate({
      length: 6,
      numbers: true,
      uppercase: false,
      symbols: false,
      lowercase: false
    });

    // Create user document
    await db.collection('users').doc(user.uid).set({
      email,
      isAdmin: false,
      purchasedStorage: 0,
      emailVerified: false,
      verification: {
        otp,
        expires: admin.firestore.Timestamp.fromDate(new Date(Date.now() + 600000))
      },
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      plan: 'free',
      resources: {
        storageUsed: 0,
        cpuUsed: 0
      }
    });

    // Send verification email
    const msg = {
      to: email,
      from: process.env.SENDGRID_FROM_EMAIL,
      subject: 'Verify Your Email Address',
      text: `Your verification code is: ${otp}`
    };
    
    await sgMail.send(msg);

    res.json({ success: true });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(400).json({ 
     error: error.code === 'auth/email-already-in-use'  // Correct error code
    ? 'Email already registered' 
    : 'Registration failed' 
});
  }
});

// Email Verification Middleware
const checkEmailVerified = async (req, res, next) => {
  try {
    const userDoc = await req.userRef.get();
    const userData = userDoc.data();
    
    if (!userData.emailVerified) {
      return res.status(403).json({ 
        error: 'Email verification required',
        code: 'EMAIL_NOT_VERIFIED'
      });
    }
    
    next();
  } catch (error) {
    res.status(500).json({ error: 'Verification check failed' });
  }
};


app.post('/test-email', async (req, res) => {
  try {
    const msg = {
      to: 'shaikhmujahid771@gmail.com',
      from: process.env.SENDGRID_FROM_EMAIL,
      subject: 'SendGrid Test',
      text: 'Successful configuration test'
    };
    
    await sgMail.send(msg);
    res.json({ success: true });
  } catch (error) {
    console.error('Email test failed:', error);
    res.status(500).json({ error: error.response.body.errors });
  }
});
// Send Verification OTP
app.post('/send-verification-otp', async (req, res) => {
  try {
    const userDoc = await req.userRef.get();
    const userData = userDoc.data();

    // Generate new OTP
    const otp = otpGenerator.generate({
      length: 6,
      numbers: true,
      uppercase: false,
      symbols: false,
      lowercase: false
    });

    // Update user document
    await req.userRef.update({
      verification: {
        otp,
        expires: admin.firestore.Timestamp.fromDate(new Date(Date.now() + 600000))
      }
    });

    // Send email
    const msg = {
      to: userData.email,
      from: process.env.SENDGRID_FROM_EMAIL,
      subject: 'New Verification Code',
      text: `Your new verification code is: ${otp}`
    };
    
    await sgMail.send(msg);

    res.json({ success: true });
  } catch (error) {
    console.error('OTP send error:', error);
    res.status(500).json({ error: 'Failed to send OTP' });
  }
});

// Verify OTP
app.post('/verify-otp', async (req, res) => {
  try {
    const { otp } = req.body;
    const userDoc = await req.userRef.get();
    const userData = userDoc.data();

    if (!userData.verification) {
      return res.status(400).json({ error: 'No pending verification' });
    }

    if (admin.firestore.Timestamp.now().toMillis() > userData.verification.expires.toMillis()) {
      return res.status(400).json({ error: 'OTP expired' });
    }

    if (otp !== userData.verification.otp) {
      return res.status(400).json({ error: 'Invalid OTP' });
    }

    // Update user as verified
    await req.userRef.update({
      emailVerified: true,
      verification: admin.firestore.FieldValue.delete()
    });

    res.json({ success: true });
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});


// User Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Enhanced Firebase REST API call
    const firebaseResponse = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${process.env.FIREBASE_WEB_API_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email,
          password: password,
          returnSecureToken: true
        })
      }
    );

    const authData = await firebaseResponse.json();
    
    // Detailed error handling
    if (!firebaseResponse.ok) {
      console.error('Firebase Auth Error:', authData.error);
      const errorMap = {
        'EMAIL_NOT_FOUND': 'Email not registered',
        'INVALID_PASSWORD': 'Incorrect password',
        'USER_DISABLED': 'Account disabled'
      };
      return res.status(401).json({ 
        error: errorMap[authData.error.message] || 'Authentication failed' 
      });
    }

    // Verify user document exists
    const user = await admin.auth().getUser(authData.localId);
    const userDoc = await db.collection('users').doc(user.uid).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User profile not found' });
    }

    // Update last login
    await db.collection('users').doc(user.uid).update({
      lastLogin: admin.firestore.FieldValue.serverTimestamp()
    });

    // Set session
    req.session.uid = user.uid;
    req.session.isAdmin = userDoc.data().isAdmin;

    res.json({ success: true });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      error: error.message || 'Login failed. Please try again.' 
    });
  }
});

// Add this endpoint to complete purchases
app.post('/complete-purchase', async (req, res) => {
  try {
    const userDoc = await req.userRef.get();
    const userData = userDoc.data();
    
    // Add purchased storage
    await req.userRef.update({
      'purchasedStorage': admin.firestore.FieldValue.increment(50)
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Complete purchase error:', error);
    res.status(500).json({ error: 'Failed to complete purchase' });
  }
});

// Apply middleware to protected routes
app.post('/purchase-storage', async (req, res) => {
  try {
    const { paymentMethodId, billingDetails } = req.body;
    const country = billingDetails.address.country || 'US';
    
    // Verify user authentication
    if (!req.session.uid) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Get user reference
    const userRef = db.collection('users').doc(req.session.uid);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userData = userDoc.data();
 // Determine currency and amount
    let currency, amount;
    if (country === 'IN') {
      currency = 'inr';
      amount = 12500; // ₹125 in paise
    } else {
      currency = 'usd';
      amount = 150; // $1.50 in cents
    }

    // Create or get customer
    let customerId = userData.stripeCustomerId;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: userData.email,
        name: billingDetails.name,
        address: billingDetails.address
      });
      customerId = customer.id;
      await req.userRef.update({ stripeCustomerId: customerId });
    } else {
      await stripe.customers.update(customerId, {
        name: billingDetails.name,
        address: billingDetails.address
      });
    }

    // Create PaymentIntent with dynamic currency
    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency,
      customer: customerId,
      payment_method: paymentMethodId,
      confirm: true,
      setup_future_usage: 'off_session',
      description: '50GB Storage Purchase',
      metadata: {
        product: 'cloud_storage',
        size_gb: '50',
        user_id: req.session.uid,
        currency: currency // Store currency in metadata
      },
      payment_method_types: ['card'],
      payment_method_options: {
        card: {
          request_three_d_secure: 'any'
        }
      },
      shipping: {
        name: billingDetails.name,
        address: billingDetails.address
      }
    });

    // Handle payment status
    if (paymentIntent.status === 'succeeded') {
      return res.json({ 
        success: true,
        payment_intent_id: paymentIntent.id
      });
    }

    if (paymentIntent.status === 'requires_action') {
      return res.json({
        requires_action: true,
        client_secret: paymentIntent.client_secret,
        payment_intent_id: paymentIntent.id
      });
    }

    res.status(400).json({ error: `Payment status: ${paymentIntent.status}` });
    

  } catch (error) {
    console.error('Purchase error:', error);
    let errorMessage = error.message;
    if (error.code === 'amount_too_small') {
      errorMessage = 'Minimum amount is ₹50.00 for Indian transactions';
    } else if (error.code === 'currency_not_supported') {
      errorMessage = 'Only INR currency supported for Indian accounts';
    }
    res.status(500).json({ error: errorMessage });
  }
});

// Add this after the /purchase-storage endpoint
app.post('/confirm-payment', async (req, res) => {
  try {
    const { paymentIntentId } = req.body;
    
    // Verify user authentication
    if (!req.session.uid) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Retrieve payment intent from Stripe
    const paymentIntent = await stripe.paymentIntents.retrieve(paymentIntentId);
    
    // Verify payment status
    if (paymentIntent.status !== 'succeeded') {
      return res.status(400).json({ 
        error: `Payment status is ${paymentIntent.status} - expected succeeded`
      });
    }

    // Update user storage
    const userRef = db.collection('users').doc(req.session.uid);
    await userRef.update({
      'purchasedStorage': admin.firestore.FieldValue.increment(50)
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Payment confirmation error:', error);
    res.status(500).json({ 
      error: error.message || 'Payment confirmation failed' 
    });
  }
});

app.post('/upload', checkEmailVerified, upload.single('file'), async (req, res) => {
  try {
    const userDoc = await req.userRef.get();
    const userData = userDoc.data();
    const file = req.file;
    
    if (!file) return res.status(400).json({ error: 'No file uploaded' });
    
    const fileSizeGB = file.size / (1024 * 1024 * 1024);
    const newStorageUsed = userData.resources.storageUsed + fileSizeGB;
    
    const baseStorage = userData.plan === 'free' ? 2 : 1024;
    const purchasedStorage = userData.purchasedStorage || 0;
    const storageLimit = baseStorage + purchasedStorage;

    if (newStorageUsed > storageLimit) {
      return res.status(400).json({ 
        error: 'Your storage limit has been exceeded',
        requiresUpgrade: true
      });
    }

    // Upload to Firebase Storage
    const fileRef = bucket.file(`users/${req.session.uid}/${Date.now()}_${file.originalname}`);
    await fileRef.save(file.buffer, {
      metadata: { contentType: file.mimetype }
    });

    // Get download URL
    const [url] = await fileRef.getSignedUrl({
      action: 'read',
      expires: '03-09-2491'
    });

    // Store metadata
    await req.userRef.collection('files').add({
      name: file.originalname,
      size: fileSizeGB,
      type: file.mimetype,
      url,
      path: fileRef.name,
      uploadedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Update storage usage
    await req.userRef.update({
      'resources.storageUsed': newStorageUsed
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'File upload failed' });
  }
});

    

// File Management Endpoints
app.delete('/files/:fileId', async (req, res) => {
  try {
    const fileDoc = await req.userRef.collection('files').doc(req.params.fileId).get();
    if (!fileDoc.exists) return res.status(404).json({ error: 'File not found' });
    
    const fileData = fileDoc.data();
    
    // Delete from Storage
    await bucket.file(fileData.path).delete();
    
    // Delete from Firestore
    await fileDoc.ref.delete();
    
    // Update storage usage
    await req.userRef.update({
      'resources.storageUsed': admin.firestore.FieldValue.increment(-fileData.size)
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'File deletion failed' });
  }
});

app.get('/files', async (req, res) => {
  try {
    if (!req.userRef) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const snapshot = await req.userRef.collection('files')
      .orderBy('uploadedAt', 'desc')
      .get();
      
    const files = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      // Convert Firestore Timestamp to JS Date
      uploadedAt: doc.data().uploadedAt.toDate().toISOString()
    }));
    
    res.json(files);
  } catch (error) {
    console.error('Files error:', error);
    res.status(500).json({ error: 'Failed to fetch files' });
  }
});

// Account Activation
app.post('/activate-account', async (req, res) => {
  try {
    const { paymentMethodId } = req.body;
    
    // Create Stripe customer
    const customer = await stripe.customers.create({
      payment_method: paymentMethodId,
      invoice_settings: {
        default_payment_method: paymentMethodId
      }
    });

    // Simulate AWS resource provisioning
    const awsResources = {
      storageBucket: `aicloude-${req.session.uid}-storage`,
      vcpuAllocation: 100,
      storageAllocation: 2
    };

  // In account activation endpoint
await req.userRef.update({
  stripeCustomerId: customer.id,
  awsResources,
  accountStatus: 'active',
  plan: 'free',
  purchasedStorage: 0, // Add this line
  resources: {
    storageUsed: 0,
    cpuUsed: 0
  }
});

    res.json({ success: true });
  } catch (error) {
    console.error('Activation error:', error);
    res.status(500).json({ error: 'Account activation failed' });
  }
});

// User Resources
app.get('/user-resources', async (req, res) => {
  try {
    const doc = await req.userRef.get();
    res.json(doc.data().resources);
  } catch (error) {
    res.status(500).json({ error: 'Failed to load resources' });
  }
});


// Session Check
app.get('/api/user', async (req, res) => {
  try {
    if (!req.session.uid) return res.json({ loggedIn: false });

    const userDoc = await db.collection('users').doc(req.session.uid).get();
    
    if (!userDoc.exists) {
      req.session.destroy();
      return res.json({ loggedIn: false });
    }

    res.json({
      loggedIn: true,
      user: {
        email: userDoc.data().email,
        isAdmin: userDoc.data().isAdmin,
        emailVerified: userDoc.data().emailVerified || false,
        plan: userDoc.data().plan || 'free',
        purchasedStorage: userDoc.data().purchasedStorage || 0
      }
    });
  } catch (error) {
    console.error('Session check error:', error);
    res.status(500).json({ loggedIn: false });
  }
});


// Contact Form
app.post('/contact', async (req, res) => {
  try {
    const { name, email, message } = req.body;
    
    if (!name || !email || !message) {
      return res.status(400).json({ error: 'All fields required' });
    }

    await db.collection('contacts').add({
      name,
      email,
      message,
      receivedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Contact error:', error);
    res.status(500).json({ error: 'Message submission failed' });
  }
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// Client-Side Routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error Handling
app.use((err, req, res, next) => {
  console.error('🚨 Server Error:', err);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: err.message 
  });
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
  🚀 Server running successfully
  ├─ Port: ${PORT}
  ├─ Firebase Project: ${serviceAccount.project_id}
  ├─ Database: ${firebaseApp.options.databaseURL}
  ├─ Storage: ${firebaseApp.options.storageBucket}
  ├─ Service Account: ${serviceAccount.client_email}
  └─ Stripe Mode: ${process.env.STRIPE_SECRET_KEY ? 'Live' : 'Test'}
  `);
  console.log('🔗 Health Check URL:', `http://localhost:${PORT}/health`);
});