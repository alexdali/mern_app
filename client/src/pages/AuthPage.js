import React, {useState, useEffect} from 'react';
import { useHttp } from '../hooks/http.hook';
import { useMessage } from '../hooks/message.hook';

export const AuthPage = () => {
  const message = useMessage();
  const { loading, request, error, clearError} = useHttp();
  const [form, setForm] = useState({
    email: '', password: ''
  });
  useEffect(() => {
    console.log('error useEffect', error);
    message(error);
    clearError();
  }, [error, message, clearError]);

  const changeHandler = event => {
    setForm({ ...form, [event.target.name]: event.target.value });
  }

  const registerHandler = async () => {
    try {
      const data = await request('/api/auth/register', 'POST', { ...form });
      message(data.message);
      console.log(`data: ${JSON.stringify(data)}`);
    } catch (e) {
    }
  }

  const loginHandler = async () => {
    try {
      const data = await request('/api/auth/login', 'POST', { ...form });
      message(data.message);
      console.log(`login data: ${JSON.stringify(data)}`);
    } catch (e) {
    }
  }


  return (
    <div className="row">
      <div className="col s6 offset-s3">
        <h1>Short link</h1>
        <div className="card blue darken-1">
          <div className="card-content white-text">
            <span className="card-title">Authorization</span>
            <div>
              <div className="input-field">
                <input
                  placeholder="Enter email"
                  id="email"
                  type="text"
                  name="email"
                  className="yellow-input"
                  onChange={changeHandler}
                  disabled={loading}
                />
                <label htmlFor="email">Email</label>
              </div>
              <div className="input-field">
                <input
                  placeholder="Enter password"
                  id="password"
                  type="password"
                  name="password"
                  className="yellow-input"
                  onChange={changeHandler}
                  disabled={loading}
                />
                <label htmlFor="password">Password</label>
              </div>
            </div>
          </div>
          <div className="card-action">
            <button
              className="btn yellow darken-4"
              style={{ marginRight: 10 }}
              onClick={loginHandler}
            >
              Sign In
            </button>
            <button
              className="btn grey lighten-1 black-text"
              onClick={registerHandler}
            >
            Sign Up
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}