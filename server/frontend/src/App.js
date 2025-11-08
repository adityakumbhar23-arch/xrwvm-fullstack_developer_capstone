
import LoginPanel from "./components/Login/Login";
import Register from "./components/Register/Register"; // ✅ Import your new Register component
import { Routes, Route } from "react-router-dom";

function App() {
  return (
    <Routes>
      {/*  Existing login route */}
      <Route path="/login" element={<LoginPanel />} />

      {/*  New register route */}
      <Route path="/register" element={<Register />} />
    </Routes>
  );
}

export default App;
