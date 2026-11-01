import { createFileRoute } from "@tanstack/react-router";
import { Console } from "@/components/lexis/console";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  return <Console />;
}
