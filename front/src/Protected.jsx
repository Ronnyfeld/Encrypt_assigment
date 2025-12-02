import { useEffect, useState } from 'react';
import axios from 'axios';

const Protected = ({ token }) => {                      /* 14 */
  const [message, setMessage] = useState('');           /* 15 */

  useEffect(() => {
    axios
      .get('http://localhost:5000/protected', {         /* 17 */
        headers: { Authorization: `Bearer ${token}` },
      })
      .then(res => setMessage(res.data.message))        /* 24 */
      .catch(() => setMessage('Access denied'));        /* 25 */
  }, [token]);                                          /* 16 */

  return <p>{message}</p>;
};

export default Protected;