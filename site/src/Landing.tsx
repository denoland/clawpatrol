import { Layout } from "./Layout";
import { DotField } from "./components/DotField.tsx";
import { ShadeGradient } from "./components/ShadeBar.tsx";
import { ApproversSection } from "./sections/ApproversSection";
import { ComparisonSection } from "./sections/ComparisonSection";
import { CtaSection } from "./sections/CtaSection";
import { DemoSection } from "./sections/DemoSection";
import { HeroSection } from "./sections/HeroSection";
import { ProblemSection } from "./sections/ProblemSection";
import { RulesSection } from "./sections/RulesSection";
import { RunSection } from "./sections/RunSection";
import { TestSection } from "./sections/TestSection";

export function Landing() {
  return (
    <Layout>
      <HeroSection />
      <DotField class="text-canvas-400" />
      <ProblemSection />
      <RunSection />
      <ShadeGradient color="text-navy-700" />
      <RulesSection />
      <ShadeGradient color="text-navy" invert />
      <ApproversSection />
      <TestSection />
      <DemoSection />
      <DotField class="text-canvas-400" />
      <ComparisonSection />
      <DotField class="text-canvas-400" />
      <CtaSection />
    </Layout>
  );
}
