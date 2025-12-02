import { useState } from 'react';
import LoginForm from './LoginForm';
import Protected from './Protected';

function App() {
  const [token, setToken] = useState(null);       /* 1 */

  return (
    <div>
      <h1>JWT Demo</h1>                           
      {!token ? (                                 /* 2, 13*/
        <LoginForm setToken={setToken} />         /* 2a */
      ) : (
        <Protected token={token} />               /* 2b */
      )}
    </div>
  );
}

export default App;