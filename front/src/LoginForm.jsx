import { useState } from 'react';
import axios from 'axios';
import api from '../api.jsx'

const LoginForm = ({ setToken }) => {                   /* 3 */
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  // PROFESSIONAL TIP:
  // We access the environment variable defined in .env
  // If we are local, it reads localhost. If on Render, it reads the production URL.
  // We use the "OR" (||) operator to fallback to localhost just in case.
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

  async function handleLogin(e) {
    e.preventDefault();
    try {
      const res = await axios.post('http://localhost:5000/login', { 
        username, password,
      });                                              /* 5 */
      setToken(res.data.token);                        /* 11 */
    } catch (err) {                                    /* 12 */
      alert('Login failed');
    }
  }

  return (                                      /* 4 */
    <form onSubmit={handleLogin}>
      <input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
      <input placeholder="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
      <button type="submit">Login</button>
    </form>
  );
};

export default LoginForm;