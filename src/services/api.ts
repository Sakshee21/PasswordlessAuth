// // // const BASE = "http://127.0.0.1:5000";

// // // export const Api = {
// // //   async getChallenge(username: string) {
// // //     const res = await fetch(`${BASE}/challenge/${username}`);
// // //     return res.json();
// // //   },

// // //   async verifyLogin(username: string, signature: string) {
// // //     const res = await fetch(`${BASE}/request-access`, {
// // //       method: "POST",
// // //       headers: { "Content-Type": "application/json" },
// // //       body: JSON.stringify({ username, signature }),
// // //     });
// // //     return res.json();
// // //   },

// // //   async getLogs() {
// // //     const res = await fetch(`${BASE}/get-logs`);
// // //     return res.json();
// // //   },

// // //   async verifyLogIntegrity() {
// // //     const res = await fetch(`${BASE}/verify-logs`);
// // //     const data = await res.json();
// // //     return data.integrity === "OK";
// // //   },
// // // };
// // const BASE = "http://127.0.0.1:5000";

// // export const Api = {
// //   /* 🔐 Get nonce challenge */
// //   async getLoginNonce(username: string) {
// //     const res = await fetch(`${BASE}/challenge/${username}`);
// //     return res.json();
// //   },

// //   /* 🔐 Verify login signature */
// //   async verifyLogin(username: string, signature: string) {
// //     const res = await fetch(`${BASE}/request-access`, {
// //       method: "POST",
// //       headers: { "Content-Type": "application/json" },
// //       body: JSON.stringify({ username, signature }),
// //     });
// //     return res.json();
// //   },

// //   /* 🔑 Register new user public key */
// //   async registerUser(username: string, publicKey: string) {
// //     const res = await fetch(`${BASE}/register`, {
// //       method: "POST",
// //       headers: { "Content-Type": "application/json" },
// //       body: JSON.stringify({
// //         username,
// //         public_key: publicKey,
// //       }),
// //     });
// //     return res.json();
// //   },

// //   /* 📜 Get audit logs */
// //   async getLogs() {
// //     const res = await fetch(`${BASE}/get-logs`);
// //     return res.json();
// //   },

// //   /* 🔎 Verify audit log integrity */
// //   async verifyLogIntegrity() {
// //     const res = await fetch(`${BASE}/verify-logs`);
// //     const data = await res.json();
// //     return data.integrity === "OK";
// //   },
// //   async getChallenge(username: string) {
// //     const res = await fetch(`${BASE}/challenge/${username}`);
// //     return res.json();
// //   },
// // };
// const BASE = "http://127.0.0.1:5000";

// export const Api = {
//   /* 🔑 Register new user public key */
//   async registerUser(username: string, publicKey: string) {
//     const res = await fetch(`${BASE}/register`, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({
//         username,
//         publicKey, // ✅ MUST match backend
//       }),
//     });

//     return res.json();
//   },

//   /* 🔐 Get nonce challenge */
//   async getLoginNonce(username: string) {
//     const res = await fetch(`${BASE}/challenge/${username}`);
//     return res.json();
//   },

//   /* 🔐 Verify login signature */
//   async verifyLogin(username: string, signature: string) {
//     const res = await fetch(`${BASE}/request-access`, {
//       method: "POST",
//       headers: { "Content-Type": "application/json" },
//       body: JSON.stringify({ username, signature }),
//     });

//     return res.json();
//   },

//   /* 📜 Get audit logs */
//   async getLogs() {
//     const res = await fetch(`${BASE}/get-logs`);
//     return res.json();
//   },

//   /* 🔎 Verify audit log integrity */
//   async verifyLogIntegrity() {
//     const res = await fetch(`${BASE}/verify-logs`);
//     const data = await res.json();
//     return data.integrity === "OK";
//   },
// };


const BASE = "http://127.0.0.1:5000";

export const Api = {

  async registerUser(username: string, publicKey: string) {
    const res = await fetch(`${BASE}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        publicKey,
      }),
    });
    return res.json();
  },

  async getLoginNonce(username: string) {
    const res = await fetch(`${BASE}/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });
    return res.json();
  },

  async verifyLogin(username: string, signature: string) {
    const res = await fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, signature }),
    });
    return res.json();
  },

  async getLogs() {
    const res = await fetch(`${BASE}/logs`);
    return res.json();
  },

  async verifyLogIntegrity() {
    const res = await fetch(`${BASE}/verify-logs`);
    return res.json();
  },
  async getChallenge(username: string) {
    const res = await fetch(`${BASE}/challenge/${username}`);
    return res.json();
  },

//   async getOperationChallenge(username: string, operation: string) {
//   const res = await fetch(`${BASE}/operation-challenge`, {
//     method: "POST",
//     headers: { "Content-Type": "application/json" },
//     body: JSON.stringify({ username, operation }),
//   });
//   return res.json();
// },

// async executeOperation(username: string, operation: string, nonce: string) {
//   const res = await fetch(`${BASE}/execute-operation`, {
//     method: "POST",
//     headers: { "Content-Type": "application/json" },
//     body: JSON.stringify({ username, operation, nonce }),
//   });
//   return res.json();
//},
  async getOperationChallenge(
  username: string,
  operation: string,
  context: any
  ) {
    const res = await fetch(`${BASE}/operation-challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, operation, context }),
    });
    return res.json();
  },

  async executeOperation(
    username: string,
    operation: string,
    nonce: string,
    context: any
  ) {
    const res = await fetch(`${BASE}/execute-operation`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, operation, nonce, context }),
    });
    return res.json();
  },
  async getStepUpChallenge(username: string, operation: string) {
    const res = await fetch(`${BASE}/stepup-challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, operation }),
    });
    return res.json();
  },

  async verifyStepUp(username: string, operation: string, signature: string) {
    const res = await fetch(`${BASE}/stepup-verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, operation, signature }),
    });
    return res.json();
  },
};