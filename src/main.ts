import './ui/styles.css';
import { mountApp } from './ui/app.ts';

const app = document.getElementById('app');
if (app) {
  void mountApp(app);
}
