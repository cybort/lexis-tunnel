import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export function EntropyMeter({ wire, random }: { wire: number; random: number }) {
  const data = [
    { name: "词隙", bits: Number(wire.toFixed(2)) },
    { name: "随机", bits: Number(random.toFixed(2)) },
  ];
  return (
    <div className="h-40 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <XAxis dataKey="name" tick={{ fill: "var(--color-mist)", fontSize: 12 }} axisLine={false} tickLine={false} />
          <YAxis domain={[0, 8]} tick={{ fill: "var(--color-mist)", fontSize: 12 }} axisLine={false} tickLine={false} width={32} />
          <Tooltip
            cursor={{ fill: "var(--color-panel-2)" }}
            contentStyle={{
              background: "var(--color-ink)",
              border: "1px solid var(--color-line)",
              borderRadius: 6,
              color: "var(--color-fg)",
            }}
            formatter={(value) => [`${value} bit/B`, "字节熵"]}
          />
          <Bar dataKey="bits" radius={4} maxBarSize={48}>
            <Cell fill="var(--color-sage)" />
            <Cell fill="var(--color-ember)" />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
