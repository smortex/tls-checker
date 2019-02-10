# frozen_string_literal: true

class Now
  include Singleton

  def initialize
    @now = Time.at(Time.now.to_i)
  end

  attr_reader :now
end
