import { Layout } from "./Layout";
import { DotField } from "./components/DotField.tsx";
import { ShadeGradient } from "./components/ShadeBar.tsx";
import { DemoSection } from "./sections/DemoSection";
import { ApproversSection } from "./sections/ApproversSection";
import { ComparisonSection } from "./sections/ComparisonSection";
import { CtaSection } from "./sections/CtaSection";
import { HeroSection } from "./sections/HeroSection";
import { ProblemSection } from "./sections/ProblemSection";
import { RulesSection } from "./sections/RulesSection";
import { RunSection } from "./sections/RunSection";
import { TestSection } from "./sections/TestSection";

export function Landing() {
  return (
    <Layout>
      <HeroSection />
      <ProblemSection />
      <DotField class="text-canvas-400" />
      <RunSection />
      <ShadeGradient color="text-navy-700" />
      <RulesSection />
      <ShadeGradient color="text-navy" invert />
      <ApproversSection />
      <TestSection />
      <DemoSection />
      <ComparisonSection />
      <CtaSection />
    </Layout>
  );
}
