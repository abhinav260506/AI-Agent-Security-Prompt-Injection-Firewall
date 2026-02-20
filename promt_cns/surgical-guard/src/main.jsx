import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import Popup from './popup/Popup.jsx' // Updated to point to the correct file
import './index.css'

createRoot(document.getElementById('root')).render(
    <StrictMode>
        <Popup />
    </StrictMode>,
)
