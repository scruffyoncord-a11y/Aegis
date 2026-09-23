export const metadata = {
  title: "Aegis",
  description: "AI Pentesting Agent",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body style={{ margin: 0, background: "#0b1120", color: "#e5e7eb" }}>
        {children}
      </body>
    </html>
  );
}
