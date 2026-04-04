import { Link } from 'react-router-dom'

export function NotFoundPage() {
  return (
    <section className="notice warning">
      <h2>Route Not Found</h2>
      <p>This route is not part of the initial admin/panel surface rollout.</p>
      <Link to="/admin" className="primary-btn inline-btn">
        Go to Admin Surface
      </Link>
    </section>
  )
}
